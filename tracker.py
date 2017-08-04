import datetime
import json

import attr

import click

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import jinja2

from pathlib import Path

import sqlalchemy

from twisted.application.internet import (
    StreamServerEndpointService, TimerService
)
from twisted.application.service import MultiService
from twisted.internet.defer import Deferred, maybeDeferred
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.task import react
from twisted.internet.threads import deferToThread
from twisted.web import server, wsgi

from werkzeug import routing
from werkzeug.exceptions import HTTPException
from werkzeug.utils import redirect
from werkzeug.wrappers import Response, Request


@attr.s
class RawCertificateDetails(object):
    crtsh_id = attr.ib()
    common_name = attr.ib()
    san_dns_names = attr.ib()
    issuer_common_name = attr.ib()
    expiration_date = attr.ib()


@attr.s
class CertificateTrackingDetails(object):
    certificate = attr.ib()
    added_at = attr.ib()
    revoked_at = attr.ib()


class CertificateDatabase(object):
    def __init__(self, db_uri):
        self._metadata = sqlalchemy.MetaData()
        self._certs = sqlalchemy.Table(
            "certificates", self._metadata,
            sqlalchemy.Column(
                "crtsh_id",
                sqlalchemy.Integer(),
                primary_key=True,
                nullable=False
            ),
            sqlalchemy.Column("common_name", sqlalchemy.Unicode),
            # JSON encoded array of strings.
            sqlalchemy.Column(
                "san_dns_names", sqlalchemy.Unicode, nullable=False
            ),
            sqlalchemy.Column("issuer_common_name", sqlalchemy.Unicode),
            sqlalchemy.Column(
                "expiration_date", sqlalchemy.DateTime, nullable=False
            ),
            sqlalchemy.Column(
                "added_at", sqlalchemy.DateTime, nullable=False
            ),
            sqlalchemy.Column("revoked_at", sqlalchemy.DateTime),
        )
        self._engine = sqlalchemy.create_engine(db_uri)

    def add_certificate(self, cert):
        self._engine.execute(self._certs.insert().values(
            crtsh_id=cert.certificate.crtsh_id,
            common_name=cert.certificate.common_name,
            san_dns_names=json.dumps(cert.certificate.san_dns_names),
            issuer_common_name=cert.certificate.issuer_common_name,
            expiration_date=cert.certificate.expiration_date,
            added_at=cert.added_at,
            revoked_at=cert.revoked_at,
        ))

    def already_tracked(self, crtsh_id):
        return self._engine.execute(
            sqlalchemy.sql.select([
                sqlalchemy.sql.exists(self._certs.select().where(
                    self._certs.c.crtsh_id == crtsh_id
                ))
            ])
        ).scalar()

    def _cert_from_row(self, row):
        return CertificateTrackingDetails(
            RawCertificateDetails(
                crtsh_id=row[self._certs.c.crtsh_id],
                common_name=row[self._certs.c.common_name],
                san_dns_names=json.loads(row[self._certs.c.san_dns_names]),
                issuer_common_name=row[self._certs.c.issuer_common_name],
                expiration_date=row[self._certs.c.expiration_date],
            ),
            added_at=row[self._certs.c.added_at],
            revoked_at=row[self._certs.c.revoked_at],
        )

    def get_all_certificates(self):
        certs = [
            self._cert_from_row(row) for row in
            self._engine.execute(self._certs.select())
        ]

        valid = []
        expired = []
        revoked = []
        for cert in certs:
            if cert.revoked_at is not None:
                revoked.append(cert)
            elif cert.certificate.expiration_date < datetime.datetime.utcnow():
                expired.append(cert)
            else:
                valid.append(cert)

        return valid, expired, revoked

    def mark_revoked(self, cert, revocation_date):
        cert.revoked_at = revocation_date
        self._engine.execute(
            self._certs.update().where(
                self._certs.c.crtsh_id == cert.certificate.crtsh_id
            ).values(
                revoked_at=revocation_date
            )
        )


class CrtshChecker(object):
    def __init__(self):
        self._engine = sqlalchemy.create_engine(
            "postgresql://guest@crt.sh:5432/certwatch"
        )

    def fetch_details(self, crtsh_id):
        [cert_data] = self._engine.execute(
            "SELECT certificate FROM certificate WHERE id = %s",
            [crtsh_id]
        ).fetchone()

        cert = x509.load_der_x509_certificate(
            bytes(cert_data), default_backend()
        )

        subject_cn = cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )
        issuer_cn = cert.issuer.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
        except x509.ExtensionNotFound:
            san_domains = None
        else:
            san_domains = [
                n.bytes_value.decode("utf8", "replace")
                for n in san.value if isinstance(n, x509.DNSName)
            ]

        return RawCertificateDetails(
            crtsh_id,
            ", ".join(a.value for a in subject_cn) if subject_cn else None,
            san_domains,
            ", ".join(a.value for a in issuer_cn) if issuer_cn else None,
            cert.not_valid_after,
        )

    def check_revocations(self, crtsh_ids):
        if not crtsh_ids:
            return {}
        rows = self._engine.execute("""
        SELECT
            c.id, crl.revocation_date
        FROM
            certificate c
        INNER JOIN crl_revoked crl ON
            (c.issuer_ca_id, x509_serialnumber(c.certificate)) =
            (crl.ca_id, crl.serial_number)
        WHERE
            c.id IN %s
        """, [(tuple(crtsh_ids),)])
        revocation_dates = {}
        for (crtsh_id, revocation_date) in rows:
            revocation_dates[crtsh_id] = revocation_date
        return revocation_dates


class WSGIApplication(object):
    def __init__(self, cert_db, crtsh_checker):
        self.cert_db = cert_db
        self.crtsh_checker = crtsh_checker

        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(
                str(Path(__file__).parent.joinpath("templates"))
            ),
            autoescape=True
        )

        self.url_map = routing.Map([
            routing.Rule("/", methods=["GET"], endpoint=self.home),
            routing.Rule(
                "/add-certificate/",
                methods=["POST"],
                endpoint=self.add_certificate
            ),
        ])

    def __call__(self, environ, start_response):
        request = Request(environ)
        response = self.handle_request(request)
        return response(environ, start_response)

    def handle_request(self, request):
        adapter = self.url_map.bind_to_environ(request)
        try:
            endpoint, args = adapter.match()
            return endpoint(request, **args)
        except HTTPException as e:
            return e

    def render_template(self, template_name, **context):
        t = self.jinja_env.get_template(template_name)
        return Response(t.render(context), mimetype="text/html")

    def home(self, request):
        (valid_certs, expired_certs, revoked_certs) = (
            self.cert_db.get_all_certificates()
        )
        return self.render_template(
            "home.html",
            valid_certs=valid_certs,
            expired_certs=expired_certs,
            revoked_certs=revoked_certs
        )

    def add_certificate(self, request):
        try:
            crtsh_id = int(request.form["crtsh-id"])
        except ValueError:
            return redirect("/")

        if self.cert_db.already_tracked(crtsh_id):
            return redirect("/")
        raw_cert = self.crtsh_checker.fetch_details(crtsh_id)
        revocation_dates = self.crtsh_checker.check_revocations([crtsh_id])

        cert = CertificateTrackingDetails(
            raw_cert,
            datetime.datetime.utcnow(),
            revocation_dates.get(crtsh_id),
        )
        self.cert_db.add_certificate(cert)
        return redirect("/")


def check_for_revocation(cert_db, crtsh_checker):
    print("[checking for revocations]")
    (certs, _, _) = cert_db.get_all_certificates()
    revocations = crtsh_checker.check_revocations(
        [c.certificate.crtsh_id for c in certs]
    )

    for cert in certs:
        revocation_date = revocations.get(cert.certificate.crtsh_id)
        if revocation_date is not None:
            cert_db.mark_revoked(cert, revocation_date)
    print("[done checking]")


def _chain_stop_result(service, stop):
    maybeDeferred(service.stopService).chainDeferred(stop)


def _main_for_service(reactor, service_builder):
    service = service_builder(reactor)
    service.startService()
    stop = Deferred()
    reactor.addSystemEventTrigger(
        "before", "shutdown", _chain_stop_result, service, stop
    )
    return stop


def run_service(service_builder):
    react(_main_for_service, [service_builder])


@click.group()
def cli():
    pass


@cli.command("create-database")
@click.option("--db-uri")
def create_database(db_uri):
    cert_db = CertificateDatabase(db_uri)
    cert_db._metadata.create_all(cert_db._engine)


@cli.command()
@click.option("--port", type=click.INT, default=8080)
@click.option("--db-uri")
def run(port, db_uri):
    cert_db = CertificateDatabase(db_uri)
    crtsh_checker = CrtshChecker()
    app = WSGIApplication(cert_db, crtsh_checker)

    def build_service(reactor):
        multi = MultiService()
        StreamServerEndpointService(
            TCP4ServerEndpoint(reactor, port),
            server.Site(
                wsgi.WSGIResource(reactor, reactor.getThreadPool(), app),
            )
        ).setServiceParent(multi)

        TimerService(
            # Run every 10 minutes
            10 * 60,
            lambda: deferToThread(check_for_revocation, cert_db, crtsh_checker)
        ).setServiceParent(multi)
        return multi

    run_service(build_service)


if __name__ == "__main__":
    cli()
