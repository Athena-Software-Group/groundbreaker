"""The rules' reading of a document: its type, the folder it belongs in and the evidence requirements it can satisfy,
with the cues that decided it (pure: no database).

    r = classify(text, name="Denuncia Carabinieri.pdf", kind="pdf", folder=EvidenceFolder.OTHER, identifiers=12)
    r = {"type": "police_report", "label": …, "folder": "law_enforcement", "section": "reports",
         "keys": ["police_report", "complaint_ref"], "reasons": ["text: “denuncia”", …], "score": 11,
         "confidence": "H", "alternatives": [...]}

Each type (`DOC_TYPES`) has cues in English, Italian, German and French (`CUES`: a weight and a pattern, counted once
each). The text's cues count their weight, the same cues in the file name / title count two more (a person named
it), the folder it is filed under one; a few cues come from the shape of the text (chat timestamps, an e-mail file,
an ID document's machine-readable zone, many transaction hashes). The highest score of at least `THRESHOLD` wins
(ties: the order of `DOC_TYPES`); none: "other" (a screenshot without a cue is filed as one). Confidence: H when the
score is high and clear of the next type, M, else L. A document holding any chat (a timestamped message line in
any messenger's copy format, an export's banner, a messenger's marker — "Forwarded from", "[Voice message]", an SMS
header —, "name: message" / "name - message" lines alternating, standalone message times, a screenshot's one message
time / ticks / "online") is never read as a police report, complaint, LE letter or order (a scammer posing as police
writes those words): chat_export, or other, with a note asking a person to confirm the type. A police report
without its agency on a letterhead line of its own in the first lines (`HEAD_LINES`: no sentence, no message time)
and a report number carries a note too. A chat is never read as a provider's reply either ("Support: your account
has been frozen, pay the unlock fee" is the scam). A provider's reply also counts the signals the caller reads
(`ticket`, `case_link`, `reply_status`: its ticket number, a wallet or the reference of the case, the outcome it
states), so an exchange's freeze confirmation that cites "law enforcement requests" and our "preservation request"
reads as its reply, not as a letter from law enforcement. `keys` are the requirement keys the type counts for ONCE A PERSON CONFIRMS
IT: the reading is only a suggestion (type, folder, reasons) and applies nothing by itself, no checklist "on file",
no folder move, no order gate (app.evidence_intel.service.confirm).
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass

from app.db.models import EvidenceFolder

_F = EvidenceFolder


@dataclass(frozen=True)
class DocType:
    key: str
    label: str
    folder: EvidenceFolder
    section: str | None = None
    keys: tuple[str, ...] = ()  # app.domain.playbook.EVIDENCE requirement keys it can satisfy
    order: bool = False  # an order LE / counsel supplies (the instrument gate: evidence_requirements.HELD_TYPES)


DOC_TYPES: dict[str, DocType] = {t.key: t for t in (
    DocType("ic3_complaint", "IC3 complaint", _F.LAW_ENFORCEMENT, "reports", ("police_report", "complaint_ref", "ic3_ref")),
    DocType("police_report", "Police report / complaint (denuncia, querela, Strafanzeige, plainte)", _F.LAW_ENFORCEMENT,
            "reports", ("police_report", "complaint_ref")),
    DocType("seizure_warrant", "Seizure warrant", _F.LEGAL, None, ("seizure_warrant",), True),
    DocType("freezing_order", "Freezing / seizure order", _F.LEGAL, None, (), True),
    DocType("court_order", "Court order", _F.LEGAL, None, ("court_order",), True),
    DocType("le_letter", "Letter from law enforcement", _F.LAW_ENFORCEMENT, "reports"),
    DocType("trace_report", "Trace report", _F.INVESTIGATOR_REPORTS, None, ("trace_report_run",)),
    DocType("intelligence_report", "Intelligence report", _F.INVESTIGATOR_REPORTS, None, ("trace_report_run",)),
    DocType("special_proxy", "Special power of attorney (procura speciale)", _F.LEGAL, None,
            ("special_proxy", "poa", "loa")),
    DocType("poa", "Power of attorney", _F.LEGAL, None, ("poa", "loa")),
    DocType("loa", "Letter of authority / authorisation", _F.LEGAL, None, ("loa",)),
    DocType("wire_confirmation", "Wire / transfer confirmation", _F.FINANCIAL, None, ("wire_details",)),
    DocType("bank_statement", "Bank statement", _F.FINANCIAL, None, ("ownership_proof", "wire_details")),
    DocType("exchange_statement", "Exchange account statement", _F.FINANCIAL, None, ("ownership_proof",)),
    DocType("account_statement", "Account statement", _F.FINANCIAL, None, ("ownership_proof",)),
    DocType("kyc_id_document", "ID document (KYC)", _F.FINANCIAL, None, ("victim_id",)),
    DocType("chat_export", "Chat export", _F.DIGITAL_ARTIFACTS, "messaging", ("comms_export",)),
    DocType("provider_reply", "Reply from a provider", _F.STOP_ORDERS_CORRESPONDENCE),
    DocType("email_export", "E-mail", _F.DIGITAL_ARTIFACTS, "emails", ("comms_export",)),
    DocType("invoice", "Invoice", _F.INVESTIGATOR_REPORTS),
    DocType("contract", "Contract / agreement", _F.LEGAL),
    DocType("other", "Other", _F.OTHER),
)}
ORDER_TYPES = frozenset(k for k, t in DOC_TYPES.items() if t.order)
THRESHOLD = 4
NAME_BONUS = 2
MAX_REASONS = 8
_W = r"(?<![^\W\d_])"  # a word starts here
_E = r"(?![^\W\d_])"  # … and ends here

# agencies: named by complaints and by LE letters alike (the other cues tell them apart)
AGENCY_CUES = ((3, r"carabinieri"), (3, r"polizia\s+(?:di\s+stato|postale)"), (3, r"comando\s+stazione"),
               (3, r"polizei\w*"), (3, r"gendarmerie"), (3, r"commissariat"),
               (2, r"police\s+(?:department|station|nationale)"), (3, r"sheriff['’]?s?\s+(?:office|department)"),
               (3, r"metropolitan\s+police(?:\s+service)?|constabulary"))
# (type, weight, pattern): each cue counts once per document
_CUE_TABLE: tuple[tuple[str, int, str], ...] = (
    # IC3
    ("ic3_complaint", 6, r"internet\s+crime\s+complaint\s+center"), ("ic3_complaint", 5, r"ic3(?:\.gov)?"),
    ("ic3_complaint", 3, r"complaint\s+referral\s+form"), ("ic3_complaint", 2, r"complaint\s+id"),
    ("ic3_complaint", 1, r"federal\s+bureau\s+of\s+investigation"),
    # police reports / complaints
    ("police_report", 5, r"denuncia(?:[- ]querela)?"), ("police_report", 5, r"querela"),
    ("police_report", 5, r"strafanzeige"), ("police_report", 5, r"(?:d[ée]p[ôo]t\s+de\s+)?plainte"),
    ("police_report", 5, r"police\s+report"), ("police_report", 4, r"crime\s+report"),
    ("police_report", 4, r"r[ée]c[ée]piss[ée]"), ("police_report", 3, r"esposto"),
    ("police_report", 3, r"verbale\s+di\s+(?:ricezione|denuncia)"), ("police_report", 3, r"anzeige(?:erstattung)?"),
    *((t, w, p) for t in ("police_report", "le_letter") for w, p in AGENCY_CUES),
    ("police_report", 2, r"police"), ("police_report", 2, r"proc[èe]s-verbal"),
    ("police_report", 2, r"incident\s+report"), ("police_report", 2, r"vorgangsnummer|aktenzeichen"),
    ("police_report", 1, r"complaint"),
    # US sheriff / UK vocabulary: "Offense Report", "Deputy …", "Crime reference number", Action Fraud
    ("police_report", 4, r"offen[cs]e\s+report"), ("police_report", 5, r"crime\s+reference\s+(?:number|no\.?)"),
    ("police_report", 5, r"action\s+fraud"), ("police_report", 2, r"sheriff|deputy"),
    # orders
    ("seizure_warrant", 7, r"seizure\s+warrant"), ("seizure_warrant", 4, r"warrant\s+(?:to|for)\s+(?:seize|seizure)"),
    ("seizure_warrant", 3, r"18\s+U\.?S\.?C\.?\s+§*\s*98[12]"), ("seizure_warrant", 2, r"in\s+rem"),
    ("freezing_order", 6, r"(?:freezing|freeze|restraint|restraining|blocking)\s+order"),
    ("freezing_order", 6, r"sequestro\s+(?:preventivo|probatorio)"), ("freezing_order", 4, r"decreto\s+di\s+sequestro"),
    ("freezing_order", 5, r"verm[öo]gensarrest|arrestbeschluss|beschlagnahmebeschluss"),
    ("freezing_order", 5, r"ordonnance\s+de\s+(?:gel|saisie)|saisie\s+p[ée]nale|gel\s+des\s+avoirs"),
    ("freezing_order", 4, r"(?:regulation\s+\(eu\)\s+)?2018/1805"), ("freezing_order", 3, r"mareva"),
    ("freezing_order", 2, r"asset\s+freeze"),
    ("court_order", 5, r"court\s+order"), ("court_order", 5, r"it\s+is\s+(?:hereby\s+)?ordered"),
    ("court_order", 4, r"(?:united\s+states\s+)?district\s+court|high\s+court|superior\s+court"),
    ("court_order", 3, r"court\s+of\s+(?:appeal|justice|first\s+instance|competent\s+jurisdiction)"),
    ("court_order", 4, r"tribunale|giudice\s+per\s+le\s+indagini|ordinanza|decreto\s+del\s+giudice"),
    ("court_order", 4, r"amtsgericht|landgericht|gerichtsbeschluss|beschluss\s+des"),
    ("court_order", 4, r"tribunal\s+judiciaire|juge\s+d'instruction|ordonnance"),
    ("court_order", 2, r"judge|magistrate|injunction"), ("court_order", 1, r"tribunal|richter"),
    # law-enforcement letters
    ("le_letter", 4, r"law[- ]enforcement\s+(?:request|agency|officer)"), ("le_letter", 4, r"special\s+agent"),
    ("le_letter", 4, r"r[ée]quisition(?:\s+judiciaire)?"), ("le_letter", 4, r"auskunftsersuchen|ermittlungsverfahren"),
    ("le_letter", 3, r"richiesta\s+di\s+(?:informazioni|acquisizione)"), ("le_letter", 3, r"procura\s+della\s+repubblica"),
    ("le_letter", 4, r"procura\s+della\s+repubblica\s+presso\s+il\s+tribunale"),  # the prosecutor, not the court
    ("le_letter", 3, r"preservation\s+request|request\s+for\s+(?:information|preservation)"),
    ("le_letter", 3, r"europol|homeland\s+security\s+investigations|secret\s+service"),
    ("le_letter", 2, r"investigating\s+officer|officer\s+in\s+charge|we\s+are\s+investigating"),
    ("le_letter", 1, r"staatsanwaltschaft|parquet|prosecutor"),
    # reports
    ("trace_report", 5, r"trac(?:e|ing)\s+report"), ("trace_report", 5, r"fund[- ]?flow"),
    ("trace_report", 4, r"blockchain\s+(?:analysis|forensics?)|on-?chain\s+analysis"),
    ("trace_report", 3, r"transaction\s+trac(?:e|ing)"), ("trace_report", 2, r"hops?"),
    ("trace_report", 2, r"(?:tx\s*)?hash(?:es)?"),
    ("intelligence_report", 5, r"intelligence\s+report"), ("intelligence_report", 4, r"osint"),
    ("intelligence_report", 4, r"relazione\s+investigativa|ermittlungsbericht|rapport\s+d'enqu[êe]te"),
    ("intelligence_report", 3, r"subject\s+profile|threat\s+intelligence|attribution"),
    ("intelligence_report", 2, r"investigat(?:ive|ion)\s+(?:report|findings)"),
    # authority documents
    ("special_proxy", 7, r"procura\s+speciale"), ("special_proxy", 6, r"special\s+(?:power\s+of\s+attorney|proxy)"),
    ("special_proxy", 4, r"limited\s+power\s+of\s+attorney"),
    ("poa", 6, r"power\s+of\s+attorney"), ("poa", 4, r"attorney[- ]in[- ]fact"), ("poa", 4, r"vollmacht"),
    ("poa", 4, r"procuration|mandataire"), ("poa", 3, r"procura(?!\s+(?:della|di|generale\s+della)\b)"),
    ("poa", 2, r"hereby\s+appoint"),
    ("loa", 6, r"letter\s+of\s+(?:authority|authori[sz]ation)"), ("loa", 4, r"lettre\s+de\s+mandat|erm[äa]chtigung"),
    ("loa", 4, r"authori[sz]e\s+\w+(?:\s+\w+){0,4}\s+to\s+act\s+on\s+(?:my|our|its)\s+behalf"),
    ("loa", 3, r"delega|autorizzazione|autorisation|mandato"), ("loa", 2, r"mandate|on\s+my\s+behalf"),
    # money
    ("wire_confirmation", 6, r"wire\s+(?:transfer\s+)?confirmation|transfer\s+confirmation|mt\s?103"),
    ("wire_confirmation", 5, r"bonifico|contabile|[üu]berweisung(?:sbest[äa]tigung)?|virement"),
    ("wire_confirmation", 4, r"payment\s+confirmation|remittance\s+advice|zahlungsbest[äa]tigung"),
    ("wire_confirmation", 3, r"wire\s+transfer|ordering\s+customer|beneficiary\s+(?:bank|account|name)"),
    # a US bank's wire: "Outgoing Wire Transfer Details", IMAD / OMAD, Fedwire, ABA routing number
    ("wire_confirmation", 5, r"(?:outgoing|incoming|domestic|international)[\s_-]+wire(?:[\s_-]+transfer)?"),
    ("wire_confirmation", 5, (r"wire[\s_-]+(?:transfer[\s_-]+)?details|funds[\s_-]+transfer[\s_-]+(?:details|"
                             r"confirmation|request)")),
    ("wire_confirmation", 5, r"imad|omad|fedwire|fed\s+reference(?:\s+number)?"),
    ("wire_confirmation", 3, r"aba(?:\s+routing)?(?:\s+(?:number|no\.?|#))?"),
    ("wire_confirmation", 2, r"wire"),  # a bare "wire": the file name ("Wire 0814.pdf", "Chase_wire.pdf")
    ("wire_confirmation", 1, r"swift|bic"),
    ("bank_statement", 6, r"bank\s+statement|estratto\s+conto|kontoauszug|relev[ée]\s+(?:de\s+compte|bancaire)"),
    ("bank_statement", 3, r"opening\s+balance|closing\s+balance|saldo\s+(?:iniziale|finale|contabile)"),
    ("bank_statement", 2, r"iban|sort\s+code|routing\s+number"), ("bank_statement", 1, r"saldo|solde"),
    ("exchange_statement", 5, r"(?:deposit|withdrawal|trade|transaction)\s+history"),
    ("exchange_statement", 4, r"storico\s+(?:transazioni|operazioni)|transaktionshistorie|historique\s+des\s+transactions"),
    ("exchange_statement", 5, r"txid\W+refid|aclass"), ("exchange_statement", 2, r"ledgers?"),
    ("exchange_statement", 3, r"withdrawal\s+address|txid"), ("exchange_statement", 2, r"spot\s+wallet|funding\s+wallet"),
    # an exchange's transaction report / export (Coinbase-style CSV: "Transaction Type,Asset,Quantity Transacted")
    ("exchange_statement", 5, r"transactions?[\s_-]+(?:report|export|statement)|account[\s_-]+activity(?:[\s_-]+report)?"),
    ("exchange_statement", 6, r"transaction\s+type\s*,[^\n]{0,80}?quantity\s+transacted"),
    ("exchange_statement", 3, r"quantity\s+transacted|asset\s+transacted|spot\s+price\s+at\s+transaction"),
    # Binance / OKX / Bybit deposit & withdrawal history CSV: "Date(UTC),Coin,Network,Amount,…,Address,TXID,Status"
    ("exchange_statement", 6, r"(?:date|time)\s*\(utc\)\s*,\s*(?:coin|currency|asset)\s*,\s*(?:network|chain)"),
    ("exchange_statement", 5, (r"(?:coin|currency|asset)\s*,\s*(?:network|chain(?:\s+type)?)\s*,[^\n]{0,120}?"
                               r"(?:txid|tx\s*hash|transaction\s+(?:id|hash))")),
    ("account_statement", 5, r"account\s+statement|statement\s+of\s+account"),
    ("account_statement", 2, r"statement\s+period"),
    ("kyc_id_document", 6, r"passport|passaporto|reisepass|passeport"),
    ("kyc_id_document", 6, r"identity\s+card|carta\s+d'identit[àa]|personalausweis|carte\s+(?:nationale\s+)?d'identit[ée]"),
    ("kyc_id_document", 5, r"driver'?s\s+licen[cs]e|patente\s+di\s+guida|f[üu]hrerschein|permis\s+de\s+conduire"),
    ("kyc_id_document", 3, r"date\s+of\s+(?:birth|expiry)|nationality|data\s+di\s+nascita|geburtsdatum"),
    ("kyc_id_document", 2, r"kyc|codice\s+fiscale"),
    # communications
    ("chat_export", 6, r"whatsapp"), ("chat_export", 5, r"telegram|wechat|discord|signal\s+(?:chat|messenger)"),
    ("chat_export", 5, r"end-to-end\s+encrypted|crittografati\s+end-to-end|ende-zu-ende|chiffr[ée]s\s+de\s+bout"),
    ("chat_export", 4, r"chat\s+(?:history|export|log)|exported\s+chat|<media\s+omitted>"),
    ("chat_export", 4, r"exported\s+data|telegram\s+desktop"),  # a Telegram export's header
    ("chat_export", 2, r"chat|messages?"),
    ("email_export", 4, r"-{2,}\s*(?:original\s+message|forwarded\s+message)\s*-{2,}"),
    ("email_export", 2, r"e-?mail"),
    ("provider_reply", 3, (r"your\s+(?:[\w-]+\s+){0,3}?(?:request|inquiry|enquiry|ticket|case)|we\s+have\s+received\s+your|"
                           r"thank\s+you\s+for\s+(?:your|contacting|reaching\s+out)")),
    # the outcome a provider states ("We confirm that the account associated with the above deposit address has
    # been frozen", "Amount held: 0.0568 ETH", "Please quote ticket KC-… in any further correspondence")
    ("provider_reply", 5, (r"(?:the|this|that|said|above|relevant|associated|affected|reported|your|user['’]?s?)\s+"
                           r"(?:[\w-]+\s+){0,8}?(?:account|address|wallet|funds|assets|balance)s?\s+(?:[\w-]+\s+){0,3}?"
                           r"(?:has|have)\s+(?:now\s+|already\s+)?been\s+(?:frozen|blocked|restricted|suspended|locked|"
                           r"blacklisted|placed\s+on\s+hold)")),
    ("provider_reply", 3, r"(?:amount|balance|funds|assets)\s+(?:currently\s+)?(?:held|frozen|blocked|restricted|on\s+hold)"),
    ("provider_reply", 4, (r"(?:please\s+)?(?:quote|reference|include|cite)\s+(?:our\s+|this\s+|the\s+)?(?:ticket|case|"
                           r"reference)(?:\s+(?:number|no\.?|id))?\s+(?:[\w#./-]+\s+)?in\s+(?:any|all|your)"
                           r"(?:\s+(?:further|future|subsequent))?")),
    ("provider_reply", 3, r"compliance\s+team|law\s+enforcement\s+(?:response|team)|risk\s+(?:team|control)"),
    ("provider_reply", 2, r"ticket(?:\s+(?:number|id|#))?|case\s+(?:number|id)\s*[:#]"),
    ("provider_reply", 2, r"la\s+sua\s+richiesta|ihre\s+anfrage|votre\s+demande"),
    ("provider_reply", 1, r"kindly|we\s+are\s+unable|please\s+(?:provide|note)"),
    # a provider asking for a police report / LE request: the document is the reply, not the report
    ("provider_reply", 4, (r"(?:please\s+)?(?:file|submit|obtain|provide|lodge|attach|send\s+us)\s+(?:us\s+)?"
                           r"(?:a\s+|the\s+|your\s+)?police\s+report|have\s+(?:the\s+|your\s+(?:local\s+)?)?(?:police|"
                           r"law\s+enforcement)(?:\s+(?:department|agency))?\s+(?:submit|send|contact)")),
    # other papers
    ("invoice", 6, r"invoice|fattura|rechnung|facture"), ("invoice", 3, r"amount\s+due|bill\s+to|payment\s+terms"),
    ("invoice", 2, r"vat|iva|mwst|tva"),
    ("contract", 3, r"agreement|contract|contratto|vertrag|vereinbarung|contrat"),
    ("contract", 4, r"term\s+sheet|engagement\s+letter"), ("contract", 2, r"whereas|hereinafter"),
    ("contract", 2, r"the\s+parties|le\s+parti|les\s+parties|die\s+parteien"),
)
# a file name writes "Police_Report_26-012345.pdf" / "Bank-Statement-Aug.pdf": a multi-word cue's gaps take _ and -
CUES: tuple[tuple[str, int, re.Pattern], ...] = tuple(
    (t, w, re.compile(_W + "(?:{})".format(p.replace(r"\s+", r"[\s_-]+")) + _E, re.IGNORECASE))
    for t, w, p in _CUE_TABLE)
MESSENGERS = frozenset({r"whatsapp", r"telegram|wechat|discord|signal\s+(?:chat|messenger)", r"chat|messages?"})
# a police report's own reference next to its agency: "Report Number: 26-012345", "Incident # …", "Prot. n. …",
# "R.G.N.R. …", "Aktenzeichen …", "PV n° …"
_POLICE_REF = re.compile(r"\b(?:(?:police\s+)?(?:report|incident|DR|case|crime\s+reference)\s*(?:number|no\.?|nr\.?|#)"
                         r"\s*[:#]?\s*[A-Z0-9][\w/.-]*\d|NFRC\d{6,}|prot(?:\.|ocollo)\s*(?:n(?:r|o|um)?\.?)?\s*[:°º]?\s*\d[\w/.-]*|"
                         r"R\.?\s?G\.?\s?N\.?\s?R\.?\s*(?:n\.?\s*)?[:°º]?\s*\d|(?:aktenzeichen|vorgangsnummer)\s*[:.]?\s*"
                         r"[A-Z0-9][\w/.-]*\d|PV\s+n[°º]\s*\d|(?:denuncia|querela|anzeige|plainte)\s+(?:n|nr|no|n[°º])\.?\s*"
                         r"[:°º]?\s*\d[\w/.-]*)", re.IGNORECASE)
_POLICE_AGENCY = re.compile(_W + r"(?:police|sheriff['’]?s?|carabinieri|polizia|polizei\w*|gendarmerie|"
                            r"commissariat|constabulary|action\s+fraud)" + _E, re.IGNORECASE)
_BALANCES = re.compile(r"opening\s+balance|saldo\s+iniziale", re.IGNORECASE)
HEAD_LINES = 12  # the letterhead: the agency that wrote the report names itself in its first lines (a form's
# cover block included)
# a provider telling the victim to get a police report: the document is not one ("Please file a police report and
# have the police department submit a request")
_ASKS_REPORT = re.compile(r"(?:file|submit|obtain|provide|lodge|attach|send\s+us)\s+(?:us\s+)?(?:a\s+|the\s+|your\s+)?"
                          r"police\s+report|have\s+(?:the\s+|your\s+(?:local\s+)?)?(?:police|law\s+enforcement)"
                          r"(?:\s+(?:department|agency))?\s+(?:submit|send|contact)", re.IGNORECASE)
# a provider asking for an order instead ("have law enforcement send us a court order or a seizure warrant",
# "obtain a freezing order"): the document is the reply, not the order (an order serves / issues itself, never asks
# to be sent or obtained)
_ASKS_ORDER = re.compile(r"(?:send|provide|obtain|submit)\s+(?:us\s+)?(?:with\s+)?(?:a\s+|an\s+|the\s+)?"
                         r"(?:valid\s+|formal\s+)?(?:court\s+order|seizure\s+warrant|freezing\s+order|freeze\s+order|"
                         r"search\s+warrant|subpoena)", re.IGNORECASE)
_ORDERS = frozenset({"court_order", "freezing_order", "seizure_warrant"})
_MRZ = re.compile(r"^[A-Z0-9<]{30,44}$", re.MULTILINE)
_HEADERS = re.compile(r"^(?:From|Von|Da|De)\s*:.+\n(?:.*\n){0,4}?(?:Subject|Betreff|Oggetto|Objet)\s*:", re.MULTILINE | re.IGNORECASE)
_SCAN_CHARS = 60_000  # the cues read this much of the text
# a statement's ledger row: "…,Send,USDT,40000,…" / "Withdrawal | USDT | 40,000"
_LEDGER_ROW = re.compile(r"(?:^|[,;|\t])\s*[\"']?(?:send|sent|withdrawal|withdraw|deposit|outgoing\s+transfer)[\"']?\s*"
                         r"[,;|\t]", re.IGNORECASE | re.MULTILINE)


# the types a scammer's message impersonates (a police report, an LE letter, a complaint, a court's order): never read
# from a document that holds a chat
_OFFICIAL = frozenset({"police_report", "le_letter", "ic3_complaint", "court_order", "freezing_order", "seizure_warrant"})
CHAT_NOTE = "may contain an official-looking message: confirm the type"
REPORT_NOTE = "no police letterhead with a report number: confirm the type"
# --------------------------------------------------------------------------- the shape of a chat
# any one of these is chat-shaped content (a document holding it is never read as an official document):
# an export's banner / a messenger's markers ("<Media omitted>", "Forwarded from …", "[Voice message]", "image
# omitted", an SMS / iMessage header)
_CHAT_SHAPE = re.compile(r"<media\s+omitted>|messages\s+(?:and\s+calls\s+)?are\s+end-to-end\s+encrypted|"
                         r"exported\s+(?:data|chat)|telegram\s+desktop|(?:chat|conversation)\s+export|"
                         r"signal\s+conversation", re.IGNORECASE)
_CHAT_MARK = re.compile(r"^\s*(?:forwarded\s+(?:message\s+)?from|inoltrato\s+da|messaggio\s+inoltrato|weitergeleitet\s+von|"
                        r"transf[ée]r[ée]\s+de)\b|\[(?:voice\s+message|audio|photo|image|video|sticker|gif|file|"
                        r"messaggio\s+vocale|sprachnachricht|message\s+vocal)\]|<attached:|(?:image|video|audio|"
                        r"sticker|gif|document)\s+omitted|^\s*(?:text\s+message|imessage|sms|mms)\s*$",
                        re.IGNORECASE | re.MULTILINE)
# a message line with its timestamp: "[01/09/2026, 10:05:00] Anna: …", "01/09/2026, 10:05 - Anna: …" (date first),
# "[10:05, 01/09/2026] Anna: …" (WhatsApp's copy, time first), "2026-09-01 10:05 Anna: …" (ISO), "2026-09-01
# 10:05:00 | Anna | …" (an exporter's columns), "Anna, [01.09.26 10:05]" (Telegram Desktop's copy header)
_STAMP_LINES = tuple(re.compile(p, re.IGNORECASE | re.MULTILINE) for p in (
    r"^\[?\d{1,2}[./-]\d{1,2}[./-]\d{2,4},?\s+\d{1,2}[:.]\d{2}(?::\d{2})?(?:\s?[AP]M)?\]?\s*(?:[-–]\s*)?\S",
    r"^\[\d{1,2}[:.]\d{2}(?::\d{2})?(?:\s?[AP]M)?,\s*\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\]\s*\S",
    r"^\[?\d{4}-\d{2}-\d{2}[ T,]+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?\]?\s*(?:[-–]\s*)?[^\W\d_][^:\n]{0,40}:\s*\S",
    r"^\d{4}-\d{2}-\d{2}[ T]\d{1,2}:\d{2}(?::\d{2})?\s*\|\s*[^|\n]{1,40}?\s*\|[^|\n]+$",
    r"^[^\n\[\]]{1,60},\s*\[\d{1,2}\.\d{2}\.\d{2,4}\s+\d{1,2}:\d{2}(?::\d{2})?\]\s*$",
    r"^\s*\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}(?::\d{2})?\s*$",  # a Telegram export's own stamp line
    # an SMS / iMessage export's stamp line: "Sep 1, 2026 10:05:00 AM", "Today 10:05", "Ieri 21:14"
    (r"^\s*(?:(?:mon|tue|wed|thu|fri|sat|sun)\w*,?\s+)?(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\w*\.?\s+"
     r"\d{1,2},?\s+\d{4},?\s+(?:at\s+)?\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AP]M)?\s*$"),
    (r"^\s*(?:today|yesterday|oggi|ieri|heute|gestern|aujourd['’]hui|hier)(?:,|\s+at|\s+alle|\s+um|\s+à)?\s+"
     r"\d{1,2}[:.]\d{2}(?:\s?[AP]M)?\s*$"),
))
# a messenger's contact header in a screenshot ("Binance Support (verified)", "Official Support ✓") next to a
# messenger's name: a chat screenshot, whatever it says it is
_CONTACT = re.compile(r"^\s*[^\n]{1,40}?\s*(?:\((?:verified|official)\)|[✓✔☑]|\bsupport)\s*$", re.IGNORECASE | re.MULTILINE)
_MESSENGER = re.compile(r"\b(?:telegram|whatsapp|wechat|signal|discord|viber|messenger|instagram|skype)\b", re.IGNORECASE)
# a chat handle ("mod_jenny", "user4417", "anna.k") or the exporter's own "me": a "name: message" pair with one is a
# chat (a report's field labels are words, never handles)
_HANDLE = re.compile(r"^(?:[a-z][a-z0-9]*[_.][a-z0-9_.]+|[a-z]+\d+|me|io|ich|moi|yo)$")
_TG_LINE = re.compile(r"\b\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}:\d{2}\b")  # a Telegram export's stamps, anywhere
_TIME_LINE = re.compile(r"^\s*\d{1,2}[:.]\d{2}(?::\d{2})?(?:\s?[AP]M)?\s*[✓✔√]*\s*$", re.IGNORECASE | re.MULTILINE)
# a message without a timestamp: "Agent: hello", "Officer Smith: …", "Anna - ok" (a report's field labels are not:
# "Report Number: …", "Reporting Officer: …", an interview's one-letter "F: … / A: …"); a bare rank or role
# ("Officer:", "Deputy:", "Victim:") is a speaker when it alternates with another
_SPEAKER = re.compile(r"^([^\W\d_][\w .'’()&-]{0,40}?)\s*(?:[:：]|\s[-–])\s+\S")
_FIELD_WORDS = re.compile(r"\b(?:n(?:o|r|um(?:ber)?|umero)\.?|n°|ref\w*|aktenzeichen|vorgangs\w*|prot\w*|r\.?g\.?n\.?r|"
                          r"date|data|datum|time|ora|uhrzeit|heure|narrative|subject|oggetto|betreff|"
                          r"objet|location|luogo|ort|lieu|place|report\w*|verbale|case|fall|dossier|incident|address\w*|"
                          r"indirizzo|adresse|phone|tel\w*|e-?mail|name|nome|cognome|signature|firma|unterschrift|amount|"
                          r"importo|betrag|montant|wallet|tx\w*|hash|from|to|cc|sent|page|section|agency|agenzia|station|"
                          r"unit|division|department|squad|status|type|tipo|summary|sintesi|description|descrizione|"
                          r"question|answer|domanda|risposta|frage|antwort|r[ée]ponse|reported|reporting|ofc|by|of|and|"
                          r"the|form|rev|step|item|note|total|balance|period)\b", re.IGNORECASE)
# a chat screenshot's text (OCR): a message's time at the end of a line ("Ok thanks 10:07 ✓✓"; never a report's "alle
# ore 10:05", "Time: 10:05", "at 10:05", a date's time), read ticks, the contact's status line ("online", "typing…")
_IMG_TIME = re.compile(r"\b\d{1,2}[:.]\d{2}(?:\s?[AP]M)?\s*[✓✔√]*\s*$", re.IGNORECASE)
_IMG_NOT_MSG = re.compile(r"(?:\b(?:ore|at|um|à|h|uhr|alle|dalle|time|ora|heure|zeit|uhrzeit|orario)|[:：]|\d[./-]\d{2,4},?)"
                          r"\s*$", re.IGNORECASE)
_IMG_TICKS = re.compile(r"[✓✔√]{2}")
_IMG_STATUS = re.compile(r"^\s*(?:online|en\s+ligne|in\s+linea|last\s+seen\b.*|zuletzt\s+online\b.*|ultimo\s+accesso\b.*|"
                         r"vu\s+(?:pour\s+la\s+derni[eè]re\s+fois|à)\b.*|typing\W*|sta\s+scrivendo\W*|schreibt\W*|"
                         r"[ée]crit\W*)\s*$", re.IGNORECASE)


def _speaker(t: str) -> str | None:
    """The sender of a "name: message" / "name - message" line; a report's field label ("Report Number:",
    "Reporting Officer:") and an interview's one-letter "F:" / "A:" are none (a bare rank or role is one)."""
    m = _SPEAKER.match(t.strip())
    if not m:
        return None
    name = m.group(1).strip()
    words = re.findall(r"[^\W\d_]+", name)
    if len(name) < 2 or len(name.split()) > 5 or not words or all(_FIELD_WORDS.fullmatch(w) for w in words):
        return None
    return name.casefold()


def _speaker_run(lines: list[str]) -> bool:
    """≥ 3 "name: message" lines in a row, at most 3 names, one of them again after another's ("Officer Smith: … /
    Anna: … / Officer Smith: …"): a chat pasted without timestamps."""
    names = [_speaker(ln) for ln in lines]
    i = 0
    while i < len(names):
        j = i
        while j < len(names) and names[j]:
            j += 1
        run = names[i:j]
        if len(run) >= 3 and len(set(run)) in (2, 3) and any(
                run[k] == run[m] and run[k] != run[k + 1] for k in range(len(run)) for m in range(k + 2, len(run))):
            return True
        i = max(j, i + 1)
    return False


def _handle_pair(lines: list[str]) -> bool:
    """Two "name: message" lines in a row, two senders, one of them a chat handle (lower case, "_" / "." / digits) or
    "me": a short chat pasted without timestamps."""
    for a, b in itertools.pairwise(lines):
        na, nb = _SPEAKER.match(a.strip()), _SPEAKER.match(b.strip())
        if not (na and nb and _speaker(a) and _speaker(b)) or _speaker(a) == _speaker(b):
            continue
        if any(_HANDLE.match(n.group(1).strip()) for n in (na, nb)):
            return True
    return False


def _chat_shape(body: str, lines: list[str], kind: str | None) -> tuple[str | None, int]:
    """(why the document holds a chat, or None; the chat_export bonus its shape earns). Any chat-shaped content
    counts: an export's banner or a messenger's marker, one timestamped message line, "name: message" lines
    alternating, two standalone message times, a chat screenshot's one message time / ticks / status line."""
    stamped = sum(len(rx.findall(body)) for rx in _STAMP_LINES)
    if stamped >= 5 or (_CHAT_SHAPE.search(body) and stamped):
        return "chat timestamps on each line", 6
    if len(_TG_LINE.findall(body)) >= 3:
        return "a chat export's timestamps", 5
    if _speaker_run(lines):
        return "“name: message” lines", 5
    if _handle_pair(lines):
        return "“name: message” lines with a chat handle", 4
    if _CHAT_SHAPE.search(body):
        return "a chat export's banner", 0  # its cue (_CUE_TABLE) already counts
    if stamped:
        return "a timestamped chat message", 2
    if _CHAT_MARK.search(body):
        return "a messenger's marker (forwarded, voice message, an SMS header)", 2
    if len(_TIME_LINE.findall(body)) >= 2:
        return "message times on their own lines", 2
    if _MESSENGER.search(body) and _CONTACT.search(body):
        return "a messenger's contact header (a chat screenshot)", 3
    if kind == "image":
        times = any((t := _IMG_TIME.search(ln)) and not _IMG_NOT_MSG.search(ln[:t.start()]) for ln in lines)
        if times or _IMG_TICKS.search(body) or any(_IMG_STATUS.match(ln) for ln in lines):
            return "a chat screenshot (a message time, ticks, a status line)", 4
    return None, 0


# a police report's letterhead line: the agency on a line of its own, no sentence ("sono l'ispettore …", "This is DC
# Brown", "Metropolitan Police here", a question) and no message time
_NOT_LETTERHEAD = re.compile(r"\b(?:sono|this\s+is|here|qui|hier|ici|ich\s+bin|je\s+suis|i\s+am|i['’]m|we\s+are|siamo|"
                             r"wir\s+sind|nous\s+sommes|hello|hi|dear|gentile|buongiorno|guten\s+tag|bonjour)\b|\?|"
                             r"\[\d|\b\d{1,2}:\d{2}\b", re.IGNORECASE)


def _letterhead(lines: list[str]) -> bool:
    return any(_POLICE_AGENCY.search(ln) and len(ln) <= 100 and not _NOT_LETTERHEAD.search(ln)
               for ln in lines[:HEAD_LINES])


def _show(s: str) -> str:
    """The cue as matched (lexicon words only), lower-case; a cue spanning free words shows its frame, never the
    words a document put in it (a name)."""
    s = " ".join(s.split()).lower()
    if re.match(r"authori[sz]e\s", s) and "to act on" in s:
        return "authorise … to act on … behalf"
    if (m := re.search(r"(?:has|have)[\s_-]+(?:(?:now|already)[\s_-]+)?been[\s_-]+(.+)$", s)):
        return f"… has been {m.group(1)}"  # an outcome: the verb, never the account / address it names
    if re.match(r"(?:please[\s_-]+)?(?:quote|reference|include|cite)[\s_-]", s) and re.search(r"[\s_-]in[\s_-]", s):
        return "quote the ticket in further correspondence"
    if (m := re.match(r"your[\s_-]+(?:[\w-]+[\s_-]+)+(request|inquiry|enquiry|ticket|case)$", s)):
        return f"your … {m.group(1)}"
    return s if len(s) <= 40 else s[:39] + "…"


def classify(text: str | None, *, name: str | None = None, kind: str | None = None,
             folder: EvidenceFolder | str | None = None, identifiers: int = 0, provider_named: bool = False,
             ticket: bool = False, case_link: bool = False, reply_status: str | None = None) -> dict:
    """The rules' reading (see the module doc). `identifiers`: how many wallets / transactions the text names;
    `provider_named`: a catalogue provider is named in it; `ticket`: it states a ticket number (not ours);
    `case_link`: it cites the case (its reference, a wallet or transaction the case holds); `reply_status`: the
    outcome the reply classifier reads in it ("frozen", "acknowledged", …). The last three count for a provider's
    reply only when its own cues already point there (never in a chat)."""
    body = (text or "")[:_SCAN_CHARS]
    name = name or ""
    score: dict[str, int] = {}
    why: dict[str, list[str]] = {}

    def add(t: str, w: int, reason: str) -> None:
        score[t] = score.get(t, 0) + w
        if reason not in why.setdefault(t, []):
            why[t].append(reason)

    lines = [ln for ln in body.splitlines() if ln.strip()]
    chat_why, chat_bonus = _chat_shape(body, lines, kind)
    asks_report = bool(_ASKS_REPORT.search(body))
    asks_order = bool(_ASKS_ORDER.search(body))
    # the agency's own report: its agency in the letterhead (the first lines), a report number, and no chat in it
    own_report = chat_why is None and not asks_report and _letterhead(lines) and bool(_POLICE_REF.search(body))
    for (t, w, rx), (_t, _w, raw) in zip(CUES, _CUE_TABLE, strict=True):
        m = rx.search(body) if body else None
        if m:
            # a messaging app a document names is a chat only when the document holds one
            w_text = w if t != "chat_export" or chat_why or raw not in MESSENGERS else max(1, w // 2)
            add(t, w_text, f"text: “{_show(m.group(0))}”")
        n = rx.search(name) if name else None
        if n:
            add(t, w + NAME_BONUS, f"file name: “{_show(n.group(0))}”")
    if chat_bonus:
        add("chat_export", chat_bonus, chat_why)
    if own_report and score.get("provider_reply", 0) < 3:
        add("police_report", 6, "a police agency and its report number")
    if asks_report and score.get("police_report"):
        add("police_report", -5, "asks for a police report (a reply, not the report)")
    if asks_order:
        for t in sorted(_ORDERS):
            if score.get(t):
                add(t, -score[t], "asks for an order (a reply, not the order)")
        if score.get("provider_reply"):
            add("provider_reply", 3, "asks for an order (a provider's reply)")
    if (_BALANCES.search(body) and re.search(r"closing\s+balance|saldo\s+finale", body, re.IGNORECASE)
            and re.search(r"statement\s+period|account\s+statement|estratto\s+conto", body, re.IGNORECASE)):
        add("bank_statement", 8, "a statement's period with its opening and closing balances")  # a wire it lists is a row
    ledger = bool(re.search(r"txid\W+refid|^[^\n]*\btype\b[^\n]*,[^\n]*\basset\b[^\n]*,[^\n]*\bamount\b", body,
                            re.IGNORECASE | re.MULTILINE))
    if ledger and len(_LEDGER_ROW.findall(body)) >= 1:
        add("exchange_statement", 4, "a ledger export with deposit / withdrawal rows")
    if kind == "email":
        add("email_export", 4, "an e-mail file")
        if provider_named and score.get("provider_reply", 0) >= 3:
            add("provider_reply", 4, "an e-mail from a provider answering a request")
    elif len(_HEADERS.findall(body)) >= 1:
        add("email_export", 2, "e-mail headers in the text")
    if provider_named and score.get("provider_reply", 0):
        add("provider_reply", 1, "names a provider")
    if chat_why is None and not own_report and score.get("provider_reply", 0) >= 2:
        # a provider answering a request: its own ticket number, this case's reference or a wallet the case holds,
        # an outcome it states (the reply classifier's reading). Its words about "law enforcement requests" or a
        # "preservation request" cite our letter or its policy: an LE letter is written by an agency.
        if ticket and provider_named:
            add("provider_reply", 3, "a provider's ticket number")
        if case_link:
            add("provider_reply", 2, "cites this case (its reference or a wallet it holds)")
        if reply_status:
            add("provider_reply", 4, f"states an outcome ({reply_status})")
    if len(_MRZ.findall(body)) >= 2 or re.search(r"^P<[A-Z]{3}", body, re.MULTILINE):
        add("kyc_id_document", 6, "a machine-readable zone (ID document)")
    if identifiers >= 6:
        add("trace_report", 3, f"names {identifiers} wallets / transactions")
    if provider_named and len(_LEDGER_ROW.findall(body)) >= 1:
        add("exchange_statement", 4, "names an exchange, with send / withdrawal rows")
    try:
        f = EvidenceFolder(folder) if folder else None
    except ValueError:
        f = None
    if f is not None and f != _F.OTHER:
        for t in list(score):
            if DOC_TYPES[t].folder == f:
                add(t, 1, f"filed under {f.value.replace('_', ' ')}")
    for spec in ("seizure_warrant", "freezing_order"):  # an order of a kind: the court's cues count for it too
        if score.get(spec, 0) >= 5 and score.get("court_order"):
            add(spec, score["court_order"], "issued by a court")
    floor = 3 if kind == "image" else THRESHOLD
    ranked = sorted(score.items(), key=lambda kv: (-kv[1], list(DOC_TYPES).index(kv[0])))
    note = None
    if chat_why:
        # a document holding a chat is never read as a police report, a complaint, an LE letter or an order (a scammer
        # posing as police writes those words in a message): a person confirms the type
        if any(t in _OFFICIAL and s >= 3 for t, s in ranked) or _POLICE_REF.search(body):
            note = CHAT_NOTE  # an agency, an order's words or a report number in it
        # nor as a provider's reply: "Support: your account has been frozen, pay the unlock fee" is the scam itself
        pick = [(t, s) for t, s in ranked if t not in _OFFICIAL and t != "provider_reply"]
    else:
        pick = ranked
    best, top = (pick[0] if pick and pick[0][1] >= floor else ("other", 0))
    if note and best != "chat_export":
        best, top = ("chat_export", score["chat_export"]) if score.get("chat_export", 0) >= floor else ("other", 0)
    second = next((s for t, s in ranked if t != best), 0)
    conf = "H" if top >= 10 and top - second >= 4 else "M" if top >= 6 and top - second >= 2 else "L"
    dt = DOC_TYPES[best]
    folder_out, section = dt.folder, dt.section
    if best == "other" and kind == "image":
        folder_out, section = _F.DIGITAL_ARTIFACTS, "screenshots"
    if best != "other":
        reasons = why[best]
    else:
        reasons = ["no type scored high enough"] if ranked else ["no cue matched"]
    keys = list(dt.keys)  # what the type counts for once a person confirms it: a suggestion satisfies nothing
    if best == "police_report" and not own_report:
        note = REPORT_NOTE  # not the agency's own report by its shape: say so to the person who confirms
    if note and conf == "H":
        conf = "M"
    return {"type": best, "label": dt.label, "folder": folder_out.value, "section": section, "keys": keys,
            "reasons": reasons[:MAX_REASONS], "note": note,
            "score": top, "confidence": conf if best != "other" else "L",
            "alternatives": [{"type": t, "label": DOC_TYPES[t].label, "score": s} for t, s in ranked
                             if t != best and s >= 3][:2]}


def type_of(key: str | None) -> DocType | None:
    return DOC_TYPES.get(key or "")
