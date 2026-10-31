"""Aegis e-mail plumbing: transports (none / file / Microsoft Graph), inbound parsing, matching and
mailbox ingestion. Owner: the mail feature. Composing and sending live in
app.domain.mail_compose / app.domain.mail_send; nothing under app/ai/ may import this package.

    app.mail.config     MailSettings (AEGIS_MAIL_*, AEGIS_M365_*), read fresh on every call
    app.mail.transport  the transport contract, NoneTransport, FileTransport, get_transport()
    app.mail.graph      GraphClient / GraphTransport (client-credentials, MIME draft + send)
    app.mail.inbound    parse raw MIME, HTML -> text, auto-reply / bounce detection
    app.mail.matching   which case / letter an inbound message answers
    app.mail.ingest     sync_mailbox (lease, cutover, dedupe), persist_to_case, triage
"""
