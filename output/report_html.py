from datetime import datetime
from jinja2 import Template

TEMPLATE = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dolos — {{ filename }}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap');

        :root {
            --bg:        #080b10;
            --surface:   #0e1219;
            --surface2:  #141820;
            --border:    #1e2433;
            --text:      #c9d1e0;
            --muted:     #4a5568;
            --accent:    #3b82f6;

            --critical:  #ef4444;
            --high:      #f97316;
            --medium:    #eab308;
            --low:       #3b82f6;

            --pass:      #22c55e;
            --fail:      #ef4444;
            --none:      #4a5568;

            --verdict-color: {{ score.color }};
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg);
            color: var(--text);
            padding: 40px 20px;
            min-height: 100vh;
        }

        .container { max-width: 860px; margin: 0 auto; }

        /* ── HEADER ── */
        .page-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 32px;
        }
        .logo {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--accent);
            letter-spacing: 2px;
            text-transform: uppercase;
        }
        .logo-sep { color: var(--muted); margin: 0 4px; }
        .page-meta {
            font-size: 0.78rem;
            color: var(--muted);
            font-family: 'JetBrains Mono', monospace;
        }

        /* ── VERDICT ── */
        .verdict-card {
            border: 1px solid var(--verdict-color);
            border-radius: 6px;
            padding: 24px 28px;
            margin-bottom: 24px;
            position: relative;
            overflow: hidden;
            background: var(--surface);
        }
        .verdict-card::before {
            content: '';
            position: absolute;
            inset: 0;
            background: var(--verdict-color);
            opacity: 0.04;
        }
        .verdict-top {
            display: flex;
            align-items: baseline;
            gap: 16px;
            margin-bottom: 14px;
        }
        .verdict-label {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.6rem;
            font-weight: 700;
            color: var(--verdict-color);
            letter-spacing: 1px;
        }
        .verdict-count {
            font-size: 0.82rem;
            color: var(--muted);
        }
        .score-bar-wrap {
            background: var(--border);
            border-radius: 2px;
            height: 4px;
            width: 100%;
        }
        .score-bar {
            height: 4px;
            border-radius: 2px;
            background: var(--verdict-color);
            width: {{ score.score }}%;
            transition: width 0.6s ease;
        }
        .score-labels {
            display: flex;
            justify-content: space-between;
            margin-top: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            color: var(--muted);
        }
        .score-num {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
            color: var(--verdict-color);
        }

        /* ── SECTIONS ── */
        .section {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px 24px;
            margin-bottom: 16px;
        }
        .section-title {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: var(--muted);
            margin-bottom: 16px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
        }

        /* ── FIELDS ── */
        .field {
            display: flex;
            gap: 12px;
            margin-bottom: 8px;
            font-size: 0.85rem;
            align-items: baseline;
        }
        .field:last-child { margin-bottom: 0; }
        .fk {
            color: var(--muted);
            min-width: 130px;
            flex-shrink: 0;
            font-size: 0.8rem;
        }
        .fv {
            color: var(--text);
            word-break: break-all;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
        }

        /* ── BADGES ── */
        .badge {
            display: inline-block;
            padding: 1px 7px;
            border-radius: 3px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.5px;
        }
        .badge-pass { background: #052210; color: var(--pass); border: 1px solid #0a3a1a; }
        .badge-fail { background: #1f0505; color: var(--fail); border: 1px solid #3a0a0a; }
        .badge-none { background: #111; color: var(--muted); border: 1px solid var(--border); }

        /* ── ANOMALIES ── */
        .anomaly {
            display: grid;
            grid-template-columns: 3px 1fr auto;
            gap: 0 14px;
            align-items: start;
            padding: 10px 0;
            border-bottom: 1px solid var(--border);
        }
        .anomaly:last-child { border-bottom: none; padding-bottom: 0; }
        .anomaly:first-child { padding-top: 0; }
        .anomaly-bar { border-radius: 2px; height: 100%; min-height: 36px; }
        .anomaly-bar.critical { background: var(--critical); }
        .anomaly-bar.high     { background: var(--high); }
        .anomaly-bar.medium   { background: var(--medium); }
        .anomaly-bar.low      { background: var(--low); }
        .anomaly-type {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 3px;
        }
        .anomaly-desc { font-size: 0.8rem; color: var(--muted); }
        .anomaly-score {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            color: var(--muted);
            white-space: nowrap;
            align-self: center;
        }
        .sev-tag {
            display: inline-block;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.65rem;
            padding: 1px 5px;
            border-radius: 2px;
            margin-right: 6px;
            vertical-align: middle;
        }
        .sev-critical { background: #2a0808; color: var(--critical); }
        .sev-high     { background: #2a1408; color: var(--high); }
        .sev-medium   { background: #2a2008; color: var(--medium); }
        .sev-low      { background: #08142a; color: var(--low); }

        /* ── URL ── */
        .url-row {
            padding: 8px 10px;
            background: var(--surface2);
            border-radius: 4px;
            margin-bottom: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.76rem;
        }
        .url-row:last-child { margin-bottom: 0; }
        .url-original { color: var(--text); word-break: break-all; }
        .url-redirect { color: var(--accent); margin-top: 4px; word-break: break-all; }
        .url-redirect::before { content: '→ '; color: var(--muted); }
        .url-error { color: var(--fail); margin-top: 4px; }
        .url-vt {
            margin-top: 5px;
            display: flex;
            gap: 8px;
            font-size: 0.72rem;
        }
        .vt-clean  { color: var(--pass); }
        .vt-hit    { color: var(--fail); font-weight: 700; }
        .vt-muted  { color: var(--muted); }

        /* ── ATTACHMENTS ── */
        .attachment-block {
            background: var(--surface2);
            border-radius: 4px;
            padding: 14px;
            margin-bottom: 10px;
        }
        .attachment-block:last-child { margin-bottom: 0; }
        .att-name {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 10px;
        }
        .hash-row {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            color: var(--muted);
            word-break: break-all;
            margin-bottom: 3px;
        }
        .hash-label { color: var(--border); margin-right: 6px; }

        /* ── PDF ANALYSIS ── */
        .pdf-block {
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid var(--border);
        }
        .pdf-label {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            color: var(--muted);
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-bottom: 6px;
        }
        .pdf-flag {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            color: var(--critical);
            margin-bottom: 4px;
        }
        .pdf-url {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.74rem;
            color: var(--muted);
            word-break: break-all;
            padding: 3px 6px;
            background: var(--surface);
            border-radius: 3px;
            margin-bottom: 3px;
        }

        /* ── VT ATTACHMENT ── */
        .vt-block {
            margin-top: 8px;
            padding: 8px 10px;
            background: var(--surface);
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.76rem;
        }

        /* ── EMPTY ── */
        .empty { color: var(--muted); font-size: 0.82rem; font-style: italic; }

        /* ── NO ANOMALIES ── */
        .no-anomalies {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--pass);
        }

        /* ── FOOTER ── */
        .footer {
            text-align: center;
            color: var(--muted);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            margin-top: 32px;
            letter-spacing: 1px;
        }

        /* ── GRID ── */
        .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        @media (max-width: 600px) { .grid2 { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
<div class="container">

    <!-- PAGE HEADER -->
    <div class="page-header">
        <div>
            <div class="logo">DOLOS<span class="logo-sep">/</span>{{ filename }}</div>
            <div class="page-meta">{{ timestamp }}</div>
        </div>
    </div>

    <!-- VERDICT -->
    <div class="verdict-card">
        <div class="verdict-top">
            <div class="verdict-label">{{ score.verdict }}</div>
            <div class="verdict-count">{{ score.anomaly_count }} anomal{% if score.anomaly_count == 1 %}y{% else %}ies{% endif %} · {{ score.score }}/100</div>
        </div>
        <div class="score-bar-wrap">
            <div class="score-bar"></div>
        </div>
        <div class="score-labels">
            <span>0</span>
            <span class="score-num">{{ score.score }}</span>
            <span>100</span>
        </div>
    </div>

    <!-- HEADER + AUTH -->
    <div class="grid2">
        <div class="section">
            <div class="section-title">Sender</div>
            <div class="field">
    <span class="fk">From</span>
    <span class="fv">
        {% if sender.display_name %}
        <span style="color:var(--muted);">{{ sender.display_name }}</span>
        <span style="color:var(--border);"> &lt;</span>{{ sender.from_address }}<span style="color:var(--border);">&gt;</span>
        {% else %}
        {{ sender.from_address }}
        {% endif %}
    </span>
</div>
            {% if sender.reply_to_address %}<div class="field">
    <span class="fk">Reply-To</span>
    <span class="fv" style="{{ 'color:var(--high);' if sender.reply_to_mismatch else '' }}">{{ sender.reply_to_address }}</span>
</div>{% endif %}
            {% if headers.return_path %}<div class="field"><span class="fk">Return-Path</span><span class="fv">{{ headers.return_path }}</span></div>{% endif %}
            <div class="field"><span class="fk">Subject</span><span class="fv" style="font-family:Inter,sans-serif;">{{ headers.subject }}</span></div>
            <div class="field"><span class="fk">Date</span><span class="fv">{{ headers.date }}</span></div>
        </div>

        <div class="section">
            <div class="section-title">Authentication</div>
            <div class="field">
                <span class="fk">SPF</span>
                <span class="fv">
                    <span class="badge {{ 'badge-pass' if auth.spf == 'pass' else 'badge-fail' if auth.spf in ('fail','softfail') else 'badge-none' }}">{{ auth.spf.upper() }}</span>
                </span>
            </div>
            <div class="field">
                <span class="fk">DKIM</span>
                <span class="fv">
                    <span class="badge {{ 'badge-pass' if auth.dkim == 'pass' else 'badge-fail' if auth.dkim == 'fail' else 'badge-none' }}">{{ auth.dkim.upper() }}</span>
                </span>
            </div>
            <div class="field">
                <span class="fk">DMARC</span>
                <span class="fv">
                    <span class="badge {{ 'badge-pass' if auth.dmarc == 'pass' else 'badge-fail' if auth.dmarc == 'fail' else 'badge-none' }}">{{ auth.dmarc.upper() }}</span>
                </span>
            </div>
            {% if sender.typosquatting %}
            <div class="field" style="margin-top:8px;">
                <span class="fk">Lookalike</span>
                <span class="fv" style="color:var(--high);">
                    {% for t in sender.typosquatting %}{{ t.brand }} (d={{ t.distance }}){% if not loop.last %}, {% endif %}{% endfor %}
                </span>
            </div>
            {% endif %}
            {% if enrichment.ip_lookup %}
            <div style="margin-top:12px; padding-top:12px; border-top:1px solid var(--border);">
                <div class="field"><span class="fk">IP</span><span class="fv">{{ enrichment.ip_lookup.ip }}</span></div>
                {% if enrichment.ip_lookup.abuseipdb.found %}
                <div class="field">
                    <span class="fk">AbuseIPDB</span>
                    <span class="fv" style="color:{{ 'var(--fail)' if enrichment.ip_lookup.abuseipdb.abuse_confidence > 25 else 'var(--pass)' }};">
                        {{ enrichment.ip_lookup.abuseipdb.abuse_confidence }}% · {{ enrichment.ip_lookup.abuseipdb.country }} · {{ enrichment.ip_lookup.abuseipdb.isp }}
                    </span>
                </div>
                {% endif %}
                <div class="field">
                    <span class="fk">URLhaus</span>
                    <span class="fv" style="color:{{ 'var(--fail)' if enrichment.ip_lookup.urlhaus.found else 'var(--pass)' }};">
                        {{ 'FOUND' if enrichment.ip_lookup.urlhaus.found else 'Clean' }}
                    </span>
                </div>
            </div>
            {% endif %}
        </div>
    </div>

    <!-- URL -->
    <div class="section">
        <div class="section-title">URL — {{ body.urls | length }} found</div>
        {% if body.urls %}
            {% for url in body.urls %}
            {% set vt = namespace(data=none) %}
            {% for lu in enrichment.url_lookups %}
                {% if lu.url == url.final or lu.url == url.original %}
                    {% set vt.data = lu.virustotal %}
                {% endif %}
            {% endfor %}
            <div class="url-row">
                <div class="url-original">{{ url.original }}</div>
                {% if url.final and url.final != url.original %}
                <div class="url-redirect">{{ url.final }}</div>
                {% endif %}
                {% if url.error %}
                <div class="url-error">✗ {{ url.error }}</div>
                {% endif %}
                {% if vt.data %}
                <div class="url-vt">
                    {% if vt.data.malicious is defined and vt.data.malicious > 0 %}
                    <span class="vt-hit">▲ VT: {{ vt.data.malicious }}/{{ vt.data.total }} malicious</span>
                    {% elif vt.data.found %}
                    <span class="vt-clean">✓ VT: clean ({{ vt.data.total }} engine)</span>
                    {% elif vt.data.status is defined %}
                    <span class="vt-muted">VT: {{ vt.data.status }}</span>
                    {% elif vt.data.error is defined %}
                    <span class="vt-muted">VT: {{ vt.data.error }}</span>
                    {% endif %}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        {% else %}
            <div class="empty">No URLs extracted</div>
        {% endif %}
    </div>

    <!-- ATTACHMENTS -->
    <div class="section">
        <div class="section-title">Attachments — {{ attachment_analysis.count }}</div>
        {% if attachment_analysis.count == 0 %}
            <div class="empty">No attachments</div>
        {% else %}
            {% for att in attachment_analysis.attachments %}
            {% set vt_att = namespace(data=none) %}
            {% for ha in enrichment.attachment_hashes %}
                {% if ha.sha256 == att.hashes.sha256 %}{% set vt_att.data = ha.virustotal %}{% endif %}
            {% endfor %}
            <div class="attachment-block">
                <div class="att-name">📎 {{ att.filename }} <span style="font-weight:400;color:var(--muted);">({{ att.size_bytes }} B · {{ att.real_mime }})</span></div>
                <div class="hash-row"><span class="hash-label">MD5</span>{{ att.hashes.md5 }}</div>
                <div class="hash-row"><span class="hash-label">SHA256</span>{{ att.hashes.sha256 }}</div>

                {% if vt_att.data %}
                <div class="vt-block">
                    {% if vt_att.data.malicious is defined and vt_att.data.malicious > 0 %}
                    <span style="color:var(--fail);">▲ VT: {{ vt_att.data.malicious }}/{{ vt_att.data.total }} engines flagged this hash</span>
                    {% elif vt_att.data.found %}
                    <span style="color:var(--pass);">✓ VT: clean hash ({{ vt_att.data.total }} engine)</span>
                    {% else %}
                    <span style="color:var(--muted);">VT: hash not found in database</span>
                    {% endif %}
                </div>
                {% endif %}

                {% if att.pdf_analysis %}
                <div class="pdf-block">
                    <div class="pdf-label">PDF analysis</div>
                    {% if att.pdf_analysis.has_javascript %}
                    <div class="pdf-flag">⚠ JavaScript detected</div>
                    {% endif %}
                    {% if att.pdf_analysis.auto_action %}
                    <div style="color:var(--muted);font-size:0.78rem;">Automatic action on open (OpenAction/AA)</div>
                    {% endif %}
                    {% if att.pdf_analysis.embedded_urls %}
                    <div class="pdf-label" style="margin-top:6px;">Embedded URLs</div>
                    {% for u in att.pdf_analysis.embedded_urls %}
                    <div class="pdf-url">{{ u }}</div>
                    {% endfor %}
                    {% endif %}
                    {% if att.pdf_analysis.error is defined %}
                    <div style="color:var(--muted);font-size:0.78rem;">{{ att.pdf_analysis.error }}</div>
                    {% endif %}
                </div>
                {% endif %}

                {% if att.office_macros %}
                <div class="pdf-block">
                    <div class="pdf-label">Office Macros</div>
                    {% if att.office_macros.has_macros %}
                    <div class="pdf-flag">⚠ VBA Macros detected</div>
                    {% else %}
                    <div style="color:var(--pass);font-size:0.78rem;">No Macros found</div>
                    {% endif %}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        {% endif %}
    </div>

    <!-- ANOMALIES -->
    <div class="section">
        <div class="section-title">Anomalies — {{ score.anomaly_count }}</div>
        {% if score.anomalies %}
            {% set ordered = score.anomalies | sort(attribute='severity', reverse=False) %}
            {% for a in score.anomalies | sort(attribute='score', reverse=True) %}
            <div class="anomaly">
                <div class="anomaly-bar {{ a.severity }}"></div>
                <div>
                    <div class="anomaly-type">
                        <span class="sev-tag sev-{{ a.severity }}">{{ a.severity.upper() }}</span>{{ a.type }}
                    </div>
                    <div class="anomaly-desc">{{ a.description }}</div>
                </div>
                <div class="anomaly-score">+{{ a.score }}</div>
            </div>
            {% endfor %}
        {% else %}
            <div class="no-anomalies">✓ No anomalies detected</div>
        {% endif %}
    </div>

    <div class="footer">DOLOS PHISHING ANALYZER · {{ timestamp }}</div>

</div>
</body>
</html>
"""


def generate_html_report(filename: str, headers: dict, header_analysis: dict,
                         body_analysis: dict, attachment_analysis: dict,
                         enrichment: dict, score_result: dict) -> str:
    template = Template(TEMPLATE, autoescape=True)
    html = template.render(
        filename=filename,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        headers=headers,
        auth=header_analysis["authentication"],
        sender=header_analysis["sender"],
        body=body_analysis,
        attachment_analysis=attachment_analysis,
        enrichment=enrichment,
        score=score_result,
    )
    return html
