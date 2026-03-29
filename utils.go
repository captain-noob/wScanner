package main

import (
	"bytes"
	"html/template"
)

func GenerateHTMLReport(results ResponseResultList) (string, error) {
	const tpl = `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>wScanner Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-body: #0f1117;
            --bg-card: #1a1d27;
            --bg-card-alt: #21242f;
            --bg-hover: #252837;
            --text-main: #e4e6f0;
            --text-muted: #8b8fa7;
            --text-dim: #5a5e73;
            --border: #2a2d3a;
            --border-subtle: #222536;
            --primary: #6c8cff;
            --primary-dim: rgba(108,140,255,0.12);
            --accent-green: #3dd68c;
            --accent-green-dim: rgba(61,214,140,0.12);

            /* Status Colors */
            --s2-bg: rgba(61,214,140,0.12); --s2-text: #3dd68c; --s2-border: rgba(61,214,140,0.25);
            --s3-bg: rgba(108,140,255,0.12); --s3-text: #6c8cff; --s3-border: rgba(108,140,255,0.25);
            --s4-bg: rgba(255,170,80,0.12); --s4-text: #ffaa50; --s4-border: rgba(255,170,80,0.25);
            --s5-bg: rgba(255,90,90,0.12); --s5-text: #ff5a5a; --s5-border: rgba(255,90,90,0.25);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-body);
            color: var(--text-main);
            font-size: 13px;
            line-height: 1.5;
            min-height: 100vh;
        }

        .layout {
            max-width: 1920px;
            margin: 0 auto;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        /* ── Header ── */
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 20px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
        }
        .header-left { display: flex; align-items: center; gap: 12px; }
        .header h1 {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-main);
            letter-spacing: -0.02em;
        }
        .header .logo {
            width: 28px; height: 28px;
            background: linear-gradient(135deg, var(--primary), var(--accent-green));
            border-radius: 7px;
            display: flex; align-items: center; justify-content: center;
            font-weight: 700; font-size: 14px; color: #0f1117;
        }

        /* ── Stats Bar ── */
        .stats {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .stat-chip {
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 0.8rem;
            font-weight: 500;
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-muted);
            display: flex; align-items: center; gap: 6px;
        }
        .stat-chip .val {
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }
        .stat-chip.stat-2xx .val { color: var(--s2-text); }
        .stat-chip.stat-3xx .val { color: var(--s3-text); }
        .stat-chip.stat-4xx .val { color: var(--s4-text); }
        .stat-chip.stat-5xx .val { color: var(--s5-text); }

        /* ── Filters ── */
        .filters {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
            padding: 12px 16px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
        }
        .filters input, .filters select {
            padding: 7px 12px;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: var(--bg-card-alt);
            color: var(--text-main);
            font-family: inherit;
            font-size: 0.8rem;
            height: 34px;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .filters input { min-width: 220px; flex: 1; }
        .filters select { min-width: 130px; cursor: pointer; -webkit-appearance: none; appearance: none; padding-right: 28px;
            background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%238b8fa7' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e");
            background-position: right 8px center; background-repeat: no-repeat; background-size: 14px;
        }
        .filters input:focus, .filters select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 2px var(--primary-dim);
        }
        .filters input::placeholder { color: var(--text-dim); }
        .btn-reset-filters {
            padding: 7px 14px;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: var(--bg-card-alt);
            color: var(--text-muted);
            font-family: inherit;
            font-size: 0.8rem;
            height: 34px;
            cursor: pointer;
            transition: all 0.15s;
        }
        .btn-reset-filters:hover { background: var(--bg-hover); color: var(--text-main); }
        .filter-count {
            margin-left: auto;
            font-size: 0.78rem;
            color: var(--text-dim);
            font-family: 'JetBrains Mono', monospace;
        }

        /* ── Table ── */
        .table-wrap {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            overflow: hidden;
        }
        .table-scroll {
            overflow-x: auto;
            overflow-y: auto;
            max-height: 78vh;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 1400px;
        }
        thead { position: sticky; top: 0; z-index: 10; }
        th {
            background: var(--bg-card-alt);
            text-align: left;
            padding: 10px 14px;
            font-weight: 600;
            font-size: 0.68rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-dim);
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
            position: sticky;
            top: 0;
        }
        td {
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-subtle);
            vertical-align: top;
            font-size: 0.82rem;
            color: var(--text-main);
        }
        tbody tr { transition: background 0.12s; }
        tbody tr:hover { background: var(--bg-hover); }
        tbody tr:last-child td { border-bottom: none; }

        /* ── Column Styles ── */
        .mono { font-family: 'JetBrains Mono', monospace; font-size: 0.78em; }

        .ip-cell { font-weight: 600; color: var(--text-main); white-space: nowrap; }
        .port-cell { color: var(--primary); font-weight: 500; }

        .scheme-badge {
            display: inline-block;
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 0.68em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .scheme-https { background: var(--accent-green-dim); color: var(--accent-green); border: 1px solid rgba(61,214,140,0.2); }
        .scheme-http { background: var(--s4-bg); color: var(--s4-text); border: 1px solid var(--s4-border); }

        .status-pill {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 99px;
            font-size: 0.72em;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            letter-spacing: 0.02em;
        }
        .status-2xx { background: var(--s2-bg); color: var(--s2-text); border: 1px solid var(--s2-border); }
        .status-3xx { background: var(--s3-bg); color: var(--s3-text); border: 1px solid var(--s3-border); }
        .status-4xx { background: var(--s4-bg); color: var(--s4-text); border: 1px solid var(--s4-border); }
        .status-5xx { background: var(--s5-bg); color: var(--s5-text); border: 1px solid var(--s5-border); }

        .uri-link {
            color: var(--primary);
            text-decoration: none;
            font-weight: 500;
            word-break: break-all;
            font-size: 0.8em;
        }
        .uri-link:hover { text-decoration: underline; }

        .redirect-tag {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            margin-top: 4px;
            padding: 2px 6px;
            border-radius: 4px;
            background: var(--bg-card-alt);
            border: 1px solid var(--border-subtle);
            font-size: 0.72em;
            color: var(--text-muted);
            word-break: break-all;
        }
        .redirect-tag .arrow { color: var(--s3-text); font-weight: 600; }

        .title-cell { font-weight: 500; max-width: 200px; overflow: hidden; text-overflow: ellipsis; }
        .title-cell[title] { cursor: help; }

        .server-chip {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            background: var(--bg-card-alt);
            border: 1px solid var(--border);
            color: var(--text-main);
        }

        .meta-cell { color: var(--text-muted); font-size: 0.78em; line-height: 1.5; }
        .meta-cell .label { color: var(--text-dim); font-size: 0.9em; }

        .dns-cell { font-size: 0.78em; }
        .dns-row { display: flex; align-items: baseline; gap: 4px; margin-bottom: 2px; }
        .dns-label { color: var(--text-dim); font-weight: 600; font-size: 0.85em; min-width: 42px; }
        .dns-val { color: var(--primary); word-break: break-all; }

        .ssl-cell { font-size: 0.78em; }
        .ssl-cn { color: var(--accent-green); font-weight: 500; }
        .ssl-san { color: var(--text-muted); font-size: 0.9em; }
        .ssl-san-list { list-style: none; padding: 0; margin: 3px 0 0; }
        .ssl-san-list li { padding: 1px 0; }
        .ssl-san-list li::before { content: "•"; color: var(--text-dim); margin-right: 4px; }

        /* ── Recon items ── */
        .recon-list { list-style: none; display: flex; flex-direction: column; gap: 4px; }
        .recon-chip {
            padding: 5px 8px;
            background: var(--bg-card-alt);
            border: 1px solid var(--border-subtle);
            border-radius: 5px;
            font-size: 0.76em;
        }
        .recon-cat { color: var(--primary); font-weight: 700; font-size: 0.82em; text-transform: uppercase; letter-spacing: 0.03em; }
        .recon-hdr { color: var(--text-dim); }
        .recon-hdr-val { color: var(--text-main); word-break: break-all; }
        .recon-purpose { color: var(--text-dim); font-style: italic; font-size: 0.9em; }

        /* ── Path items ── */
        .path-list { list-style: none; display: flex; flex-direction: column; gap: 3px; max-height: 260px; overflow-y: auto; }
        .path-list::-webkit-scrollbar { width: 4px; }
        .path-list::-webkit-scrollbar-track { background: transparent; }
        .path-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
        .path-row {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 3px 6px;
            border-radius: 4px;
            font-size: 0.76em;
            font-family: 'JetBrains Mono', monospace;
            transition: background 0.1s;
        }
        .path-row:hover { background: var(--bg-hover); }
        .path-row .status-pill { font-size: 0.68em; padding: 1px 6px; min-width: 28px; text-align: center; }
        .path-name { color: var(--text-main); word-break: break-all; }
        .path-bypass {
            padding: 1px 5px;
            border-radius: 3px;
            font-size: 0.7em;
            background: var(--accent-green-dim);
            color: var(--accent-green);
            border: 1px solid rgba(61,214,140,0.2);
            white-space: nowrap;
        }
        .path-redir { color: var(--text-dim); margin-left: auto; font-size: 0.9em; white-space: nowrap; }

        /* ── Empty / No Results ── */
        .text-empty { color: var(--text-dim); }
        .no-results {
            padding: 48px;
            text-align: center;
            color: var(--text-dim);
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
        }
        .no-results svg { width: 40px; height: 40px; opacity: 0.4; }
        .no-results a { color: var(--primary); cursor: pointer; text-decoration: underline; font-size: 0.85em; }

        /* ── Scrollbar ── */
        .table-scroll::-webkit-scrollbar { width: 6px; height: 6px; }
        .table-scroll::-webkit-scrollbar-track { background: transparent; }
        .table-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 6px; }
        .table-scroll::-webkit-scrollbar-thumb:hover { background: var(--text-dim); }
    </style>
</head>
<body>

<div class="layout">
    <div class="header">
        <div class="header-left">
            <div class="logo">W</div>
            <h1>wScanner Report</h1>
        </div>
        <div class="stats" id="stats"></div>
    </div>

    <div class="filters">
        <input id="q" type="text" placeholder="Search targets, titles, headers..." oninput="applyFilters()" />
        <select id="scheme" onchange="applyFilters()">
            <option value="">All Schemes</option>
        </select>
        <select id="port" onchange="applyFilters()">
            <option value="">All Ports</option>
        </select>
        <select id="status" onchange="applyFilters()">
            <option value="">All Statuses</option>
            {{- range .StatusCodes }}
            <option value="{{.}}">{{.}}</option>
            {{- end }}
        </select>
        <select id="server" onchange="applyFilters()">
            <option value="">All Servers</option>
            {{- range .Servers }}
            <option value="{{.}}">{{.}}</option>
            {{- end }}
        </select>
        <button class="btn-reset-filters" onclick="resetFilters()">Reset</button>
        <span class="filter-count" id="filterCount"></span>
    </div>

    <div class="table-wrap">
        <div class="table-scroll">
            <table id="results">
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Port</th>
                        <th>Scheme</th>
                        <th>URI</th>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Server</th>
                        <th>Content</th>
                        <th>DNS</th>
                        <th>SSL</th>
                        <th>Recon</th>
                        <th>Paths</th>
                    </tr>
                </thead>
                <tbody>
                {{- range $i, $r := .Results }}
                <tr class="row"
                    data-status="{{$r.StatusCode}}"
                    data-server="{{$r.Server}}"
                    data-scheme="{{$r.TargetData.Scheme}}"
                    data-port="{{$r.TargetData.Port}}"
                    data-ip="{{$r.TargetData.IP}}">

                    <td class="mono ip-cell">{{ $r.TargetData.IP }}</td>

                    <td class="mono port-cell">{{ $r.TargetData.Port }}</td>

                    <td>
                        {{ if eq $r.TargetData.Scheme "https" }}
                        <span class="scheme-badge scheme-https">HTTPS</span>
                        {{ else if eq $r.TargetData.Scheme "http" }}
                        <span class="scheme-badge scheme-http">HTTP</span>
                        {{ else }}
                        <span class="scheme-badge" style="background:var(--bg-card-alt);color:var(--text-dim);border:1px solid var(--border);">{{ $r.TargetData.Scheme }}</span>
                        {{ end }}
                    </td>

                    <td class="mono">
                        <a href="{{ $r.InitialURI }}" target="_blank" class="uri-link">{{ $r.InitialURI }}</a>
                        {{- if ne $r.RedirectURi "" }}
                        <div class="redirect-tag">
                            <span class="arrow">↳</span> {{ $r.RedirectURi }}
                        </div>
                        {{- end }}
                    </td>

                    <td>
                        {{ if ne $r.PageTitle "" }}
                        <div class="title-cell" title="{{ $r.PageTitle }}">{{ $r.PageTitle }}</div>
                        {{ else }}
                        <span class="text-empty">—</span>
                        {{ end }}
                    </td>

                    <td>
                        <span class="status-pill" data-status-val="{{ $r.StatusCode }}">{{ $r.StatusCode }}</span>
                    </td>

                    <td>
                        {{- if ne $r.Server "" }}
                        <span class="server-chip">{{ $r.Server }}</span>
                        {{- else }}
                        <span class="text-empty">—</span>
                        {{- end }}
                    </td>

                    <td class="meta-cell">
                        {{- if ne $r.ContentType "" }}
                        <div>{{ $r.ContentType }}</div>
                        {{- end }}
                        {{- if ne $r.ContentLength "" }}
                        <div><span class="label">Size:</span> {{ $r.ContentLength }}</div>
                        {{- end }}
                        {{- if and (eq $r.ContentType "") (eq $r.ContentLength "") }}
                        <span class="text-empty">—</span>
                        {{- end }}
                    </td>

                    <td class="dns-cell">
                        {{- if ne $r.CNAME "" }}
                        <div class="dns-row"><span class="dns-label">CNAME</span><span class="dns-val mono">{{ $r.CNAME }}</span></div>
                        {{- end }}
                        {{- if ne $r.PTR "" }}
                        <div class="dns-row"><span class="dns-label">PTR</span><span class="dns-val mono">{{ $r.PTR }}</span></div>
                        {{- end }}
                        {{- if and (eq $r.CNAME "") (eq $r.PTR "") }}
                        <span class="text-empty">—</span>
                        {{- end }}
                    </td>

                    <td class="ssl-cell">
                        {{- if ne $r.SSLCommonName "" }}
                        <div><span class="dns-label">CN</span> <span class="ssl-cn mono">{{ $r.SSLCommonName }}</span></div>
                        {{- end }}
                        {{- if gt (len $r.SSLSANs) 0 }}
                        <ul class="ssl-san-list">
                        {{- range $r.SSLSANs }}
                        <li class="ssl-san mono">{{ . }}</li>
                        {{- end }}
                        </ul>
                        {{- end }}
                        {{- if and (eq $r.SSLCommonName "") (eq (len $r.SSLSANs) 0) }}
                        <span class="text-empty">—</span>
                        {{- end }}
                    </td>

                    <td>
                        {{- if gt (len $r.ReconInfo) 0 }}
                        <ul class="recon-list">
                        {{- range $r.ReconInfo }}
                        <li class="recon-chip">
                            <div><span class="recon-cat">{{ .CategoryName }}</span> <span class="recon-purpose">{{ .Purpose }}</span></div>
                            <div><span class="recon-hdr">{{ .HeaderName }}:</span> <span class="recon-hdr-val">{{ .HeaderValue }}</span></div>
                        </li>
                        {{- end }}
                        </ul>
                        {{- else }}
                        <span class="text-empty">—</span>
                        {{- end }}
                    </td>

                    <td>
                        {{- if gt (len $r.PathResults) 0 }}
                        <ul class="path-list">
                        {{- range $r.PathResults }}
                        <li class="path-row">
                            <span class="status-pill" data-status-val="{{ .StatusCode }}">{{ .StatusCode }}</span>
                            <span class="path-name">{{ .Path }}</span>
                            {{- if ne .BypassMethod "" }}
                            <span class="path-bypass">{{ .BypassMethod }}</span>
                            {{- end }}
                            {{- if ne .RedirectURL "" }}
                            <span class="path-redir">→ {{ .RedirectURL }}</span>
                            {{- end }}
                        </li>
                        {{- end }}
                        </ul>
                        {{- else }}
                        <span class="text-empty">—</span>
                        {{- end }}
                    </td>
                </tr>
                {{- end }}
                </tbody>
            </table>
        </div>

        <div id="none" class="no-results" style="display:none">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <div>No matching results</div>
            <a onclick="resetFilters()">Clear filters</a>
        </div>
    </div>
</div>

<script>
// 1. Stats bar
(function buildStats() {
    var rows = document.querySelectorAll('#results tbody tr');
    var total = rows.length;
    var s2=0, s3=0, s4=0, s5=0;
    rows.forEach(function(r) {
        var c = parseInt(r.getAttribute('data-status'));
        if (c >= 200 && c < 300) s2++;
        else if (c >= 300 && c < 400) s3++;
        else if (c >= 400 && c < 500) s4++;
        else if (c >= 500) s5++;
    });
    var html = '<div class="stat-chip"><span>Total</span> <span class="val">' + total + '</span></div>';
    if (s2) html += '<div class="stat-chip stat-2xx"><span>2xx</span> <span class="val">' + s2 + '</span></div>';
    if (s3) html += '<div class="stat-chip stat-3xx"><span>3xx</span> <span class="val">' + s3 + '</span></div>';
    if (s4) html += '<div class="stat-chip stat-4xx"><span>4xx</span> <span class="val">' + s4 + '</span></div>';
    if (s5) html += '<div class="stat-chip stat-5xx"><span>5xx</span> <span class="val">' + s5 + '</span></div>';
    document.getElementById('stats').innerHTML = html;
})();

// 2. Populate dropdown filters dynamically
(function populateDropdowns() {
    var rows = document.querySelectorAll('#results tbody tr');
    var schemes = {}, ports = {};
    rows.forEach(function(r) {
        var s = r.getAttribute('data-scheme');
        var p = r.getAttribute('data-port');
        if (s) schemes[s] = 1;
        if (p) ports[p] = 1;
    });
    function addOpts(id, obj, numeric) {
        var sel = document.getElementById(id);
        var arr = Object.keys(obj);
        if (numeric) arr.sort(function(a,b){ return parseInt(a)-parseInt(b); });
        else arr.sort();
        arr.forEach(function(v) {
            var o = document.createElement('option');
            o.value = v; o.textContent = v;
            sel.appendChild(o);
        });
    }
    addOpts('scheme', schemes, false);
    addOpts('port', ports, true);
})();

// 3. Colorize status pills
(function colorize() {
    document.querySelectorAll('.status-pill').forEach(function(el) {
        var c = parseInt(el.getAttribute('data-status-val'));
        if (c >= 200 && c < 300) el.classList.add('status-2xx');
        else if (c >= 300 && c < 400) el.classList.add('status-3xx');
        else if (c >= 400 && c < 500) el.classList.add('status-4xx');
        else if (c >= 500) el.classList.add('status-5xx');
    });
})();

// 4. Filtering
function norm(s) { return s ? String(s).toLowerCase().trim() : ""; }

function applyFilters() {
    var q = norm(document.getElementById('q').value);
    var scheme = norm(document.getElementById('scheme').value);
    var port = norm(document.getElementById('port').value);
    var status = norm(document.getElementById('status').value);
    var server = norm(document.getElementById('server').value);
    var rows = document.querySelectorAll('#results tbody tr');
    var shown = 0, total = rows.length;

    rows.forEach(function(r) {
        var text = norm(r.textContent);
        var ok = (q === '' || text.indexOf(q) !== -1)
              && (scheme === '' || norm(r.getAttribute('data-scheme')) === scheme)
              && (port === '' || norm(r.getAttribute('data-port')) === port)
              && (status === '' || norm(r.getAttribute('data-status')) === status)
              && (server === '' || norm(r.getAttribute('data-server')) === server);
        r.style.display = ok ? '' : 'none';
        if (ok) shown++;
    });

    document.getElementById('none').style.display = shown === 0 ? 'flex' : 'none';
    document.getElementById('results').style.display = shown === 0 ? 'none' : 'table';
    document.getElementById('filterCount').textContent = shown < total ? shown + ' / ' + total : '';
}

function resetFilters() {
    document.querySelectorAll('.filters input, .filters select').forEach(function(i){ i.value = ''; });
    applyFilters();
}
</script>
</body>
</html>`

	// Build unique lists for dropdowns
	statusSet := map[string]struct{}{}
	serverSet := map[string]struct{}{}
	ctypeSet := map[string]struct{}{}
	for _, r := range results {
		statusSet[r.StatusCode] = struct{}{}
		serverSet[r.Server] = struct{}{}
		ctypeSet[r.ContentType] = struct{}{}
	}
	statusList := make([]string, 0, len(statusSet))
	for k := range statusSet {
		statusList = append(statusList, k)
	}
	serverList := make([]string, 0, len(serverSet))
	for k := range serverSet {
		serverList = append(serverList, k)
	}
	ctypeList := make([]string, 0, len(ctypeSet))
	for k := range ctypeSet {
		ctypeList = append(ctypeList, k)
	}

	data := map[string]interface{}{
		"Results":      results,
		"StatusCodes":  statusList,
		"Servers":      serverList,
		"ContentTypes": ctypeList,
	}

	t := template.Must(template.New("report").Parse(tpl))
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
