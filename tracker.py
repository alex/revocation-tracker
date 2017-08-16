import datetime
import json
import re

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
from twisted.logger import Logger
from twisted.web import server, wsgi

from werkzeug import routing
from werkzeug.exceptions import HTTPException
from werkzeug.utils import redirect
from werkzeug.wrappers import Response, Request

import wsgi_sslify


@attr.s
class RawCertificateDetails(object):
    crtsh_id = attr.ib()
    common_name = attr.ib()
    san_dns_names = attr.ib()
    ccadb_owners = attr.ib()
    issuer_common_name = attr.ib()
    expiration_date = attr.ib()

    @property
    def owner_display(self):
        display = u"{}".format(self.issuer_common_name)
        if self.ccadb_owners:
            display += u" -- {}".format(u" / ".join(self.ccadb_owners))
        return display


@attr.s
class CertificateTrackingDetails(object):
    certificate = attr.ib()
    added_at = attr.ib()
    revoked_at = attr.ib()


@attr.s
class Batch(object):
    id = attr.ib()
    description = attr.ib()


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
            # TODO: add `nullable=False` once I've fixed prod
            sqlalchemy.Column("ccadb_owners", sqlalchemy.Unicode),
        )
        self._batches = sqlalchemy.Table(
            "batches", self._metadata,
            sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
            sqlalchemy.Column(
                "description", sqlalchemy.Unicode, nullable=False
            )
        )
        self._batch_entries = sqlalchemy.Table(
            "batch_entries", self._metadata,
            sqlalchemy.Column(
                "crtsh_id",
                sqlalchemy.Integer,
                sqlalchemy.ForeignKey("certificates.crtsh_id")
            ),
            sqlalchemy.Column(
                "batch_id",
                sqlalchemy.Integer,
                sqlalchemy.ForeignKey("batches.id")
            ),
        )
        self._engine = sqlalchemy.create_engine(db_uri)

    def add_certificates(self, certs):
        self._engine.execute(self._certs.insert().values([
            {
                "crtsh_id": cert.certificate.crtsh_id,
                "common_name": cert.certificate.common_name,
                "san_dns_names": json.dumps(cert.certificate.san_dns_names),
                "issuer_common_name": cert.certificate.issuer_common_name,
                "ccadb_owners": json.dumps(cert.certificate.ccadb_owners),
                "expiration_date": cert.certificate.expiration_date,
                "added_at": cert.added_at,
                "revoked_at": cert.revoked_at,
            }
            for cert in certs
        ]))

    def remove_certificate(self, crtsh_id):
        self._engine.execute(self._batch_entries.delete().where(
            self._batch_entries.c.crtsh_id == crtsh_id
        ))
        self._engine.execute(self._certs.delete().where(
            self._certs.c.crtsh_id == crtsh_id
        ))

    def already_tracked(self, crtsh_ids):
        rows = self._engine.execute(
            sqlalchemy.sql.select([
                self._certs.c.crtsh_id
            ]).where(
                self._certs.c.crtsh_id.in_(crtsh_ids)
            )
        ).fetchall()
        return {r for r, in rows}

    def _cert_from_row(self, row):
        return CertificateTrackingDetails(
            RawCertificateDetails(
                crtsh_id=row[self._certs.c.crtsh_id],
                common_name=row[self._certs.c.common_name],
                san_dns_names=json.loads(row[self._certs.c.san_dns_names]),
                issuer_common_name=row[self._certs.c.issuer_common_name],
                # TODO: remove the `or` once I've fixed prod
                ccadb_owners=json.loads(row[self._certs.c.ccadb_owners] or "[]"),
                expiration_date=row[self._certs.c.expiration_date],
            ),
            added_at=row[self._certs.c.added_at],
            revoked_at=row[self._certs.c.revoked_at],
        )

    def get_all_certificates(self):
        return self._get_certificates(self._certs.select())

    def _get_certificates(self, query):
        certs = [
            self._cert_from_row(row) for row in
            self._engine.execute(query)
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

    def create_batch(self, description, crtsh_ids):
        result = self._engine.execute(self._batches.insert().values(
            description=description,
        ))
        [batch_id] = result.inserted_primary_key
        self._engine.execute(self._batch_entries.insert().values([
            {
                "crtsh_id": c,
                "batch_id": batch_id
            }
            for c in crtsh_ids
        ]))
        return batch_id

    def get_all_batches(self):
        rows = self._engine.execute(self._batches.select()).fetchall()
        return [
            Batch(
                id=row[self._batches.c.id],
                description=row[self._batches.c.description],
            )
            for row in rows
        ]

    def get_description_for_batch(self, batch_id):
        return self._engine.execute(sqlalchemy.sql.select([
            self._batches.c.description
        ]).where(self._batches.c.id == batch_id)).scalar()

    def get_certificates_for_batch(self, batch_id):
        subquery = sqlalchemy.sql.select([
            self._batch_entries.c.crtsh_id
        ]).where(self._batch_entries.c.batch_id == batch_id)
        query = self._certs.select().where(
            self._certs.c.crtsh_id.in_(subquery)
        )
        return self._get_certificates(query)


class CrtshChecker(object):
    def __init__(self):
        self._engine = sqlalchemy.create_engine(
            "postgresql://guest@crt.sh:5432/certwatch"
        )

    def get_replication_lag(self):
        return self._engine.execute(
            "SELECT now() - pg_last_xact_replay_timestamp()"
        ).scalar()

    def fetch_details(self, crtsh_ids):
        rows = self._engine.execute("""
        SELECT
            c.id, c.certificate, array_agg(DISTINCT cc.ca_owner)
        FROM certificate c
        INNER JOIN ca_certificate cac ON c.issuer_ca_id = cac.ca_id
        INNER JOIN ccadb_certificate cc ON cac.certificate_id = cc.certificate_id
        WHERE c.id IN %s
        GROUP BY c.id, c.certificate
        """, [(tuple(crtsh_ids),)]).fetchall()

        details = []
        for row in rows:
            cert = x509.load_der_x509_certificate(
                bytes(row[1]), default_backend()
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

            details.append(RawCertificateDetails(
                crtsh_id=row[0],
                common_name=", ".join(a.value for a in subject_cn) if subject_cn else None,
                san_dns_names=san_domains,
                ccadb_owners=[o for o in row[2] if o is not None],
                issuer_common_name=", ".join(a.value for a in issuer_cn) if issuer_cn else None,
                expiration_date=cert.not_valid_after,
            ))
        return details

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
            routing.Rule(
                "/create-batch/",
                methods=["GET", "POST"],
                endpoint=self.create_batch,
            ),
            routing.Rule(
                "/batches/",
                methods=["GET"],
                endpoint=self.list_batches,
            ),
            routing.Rule(
                "/batch/<batch_id>/",
                methods=["GET"],
                endpoint=self.batch,
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
            return e.get_response(request.environ)

    def render_template(self, template_name, **context):
        t = self.jinja_env.get_template(template_name)
        context["crtsh_replication_lag"] = (
            self.crtsh_checker.get_replication_lag()
        )
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

    def _add_crtsh_ids(self, crtsh_ids):
        existing = self.cert_db.already_tracked(crtsh_ids)
        crtsh_ids = list(set(crtsh_ids) - existing)

        if not crtsh_ids:
            return list(existing)

        raw_certs = self.crtsh_checker.fetch_details(crtsh_ids)
        revocation_dates = self.crtsh_checker.check_revocations(crtsh_ids)

        certs = [
            CertificateTrackingDetails(
                raw_cert,
                datetime.datetime.utcnow(),
                revocation_dates.get(raw_cert.crtsh_id),
            )
            for raw_cert in raw_certs
        ]
        self.cert_db.add_certificates(certs)
        return list(existing | set(c.certificate.crtsh_id for c in certs))

    def _parse_ids(self, data):
        return [int(i) for i in re.split(r"[,\s]", data) if i.isdigit()]

    def add_certificate(self, request):
        crtsh_ids = self._parse_ids(request.form["crtsh-ids"])

        self._add_crtsh_ids(crtsh_ids)
        return redirect("/")

    def create_batch(self, request):
        if request.method == "POST":
            description = request.form["description"]
            crtsh_ids = self._parse_ids(request.form["crtsh-ids"])
            if not crtsh_ids:
                return redirect("/")

            crtsh_ids = self._add_crtsh_ids(crtsh_ids)
            batch_id = self.cert_db.create_batch(description, crtsh_ids)
            return redirect("/batch/{:d}/".format(batch_id))
        return self.render_template("create-batch.html")

    def list_batches(self, request):
        batches = self.cert_db.get_all_batches()
        return self.render_template("batches.html", batches=batches)

    def batch(self, request, batch_id):
        batch_description = self.cert_db.get_description_for_batch(batch_id)
        if batch_description is None:
            return redirect("/")

        (valid_certs, expired_certs, revoked_certs) = (
            self.cert_db.get_certificates_for_batch(batch_id)
        )
        return self.render_template(
            "batch.html",
            batch_description=batch_description,
            valid_certs=valid_certs,
            expired_certs=expired_certs,
            revoked_certs=revoked_certs
        )


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
    print("[done checking; revoked={}]".format(len(revocations)))


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


@cli.command("remove-certificate")
@click.option("--db-uri")
@click.argument("crtsh-id", type=click.INT)
def remove_certificate(db_uri, crtsh_id):
    cert_db = CertificateDatabase(db_uri)
    cert_db.remove_certificate(crtsh_id)


@cli.command()
@click.option("--port", type=click.INT, default=8080)
@click.option("--db-uri")
@click.option("--hsts/--no-hsts", default=False)
def run(port, db_uri, hsts):
    cert_db = CertificateDatabase(db_uri)
    crtsh_checker = CrtshChecker()
    app = WSGIApplication(cert_db, crtsh_checker)
    if hsts:
        app = wsgi_sslify.sslify(app, subdomains=True)

    def build_service(reactor):
        multi = MultiService()
        StreamServerEndpointService(
            TCP4ServerEndpoint(reactor, port),
            server.Site(
                wsgi.WSGIResource(reactor, reactor.getThreadPool(), app),
            )
        ).setServiceParent(multi)

        logger = Logger()
        TimerService(
            # Run every 10 minutes
            10 * 60,
            lambda: deferToThread(
                check_for_revocation, cert_db, crtsh_checker
            ).addErrback(
                lambda f: logger.failure("Error checking for revocation", f)
            )
        ).setServiceParent(multi)
        return multi

    run_service(build_service)


if __name__ == "__main__":
    cli()
