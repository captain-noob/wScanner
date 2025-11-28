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
    <title>Scan Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            /* Slate Color Palette */
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --primary: #3b82f6;
            --primary-bg: #eff6ff;
            
            /* Status Colors */
            --status-2xx-bg: #dcfce7; --status-2xx-text: #166534;
            --status-3xx-bg: #dbeafe; --status-3xx-text: #1e40af;
            --status-4xx-bg: #ffedd5; --status-4xx-text: #9a3412;
            --status-5xx-bg: #fee2e2; --status-5xx-text: #991b1b;
        }

        * { box-sizing: border-box; }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-body);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
            font-size: 14px;
            line-height: 1.5;
        }

        .container {
            max-width: 1800px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        /* --- Header & Filters --- */
        .dashboard-header {
            background: var(--bg-card);
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            border: 1px solid var(--border);
        }

        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }

        h1 { margin: 0; font-size: 1.5rem; font-weight: 700; color: var(--text-main); letter-spacing: -0.025em; }
        .meta-tag { background: var(--bg-body); padding: 4px 12px; border-radius: 99px; font-size: 0.85rem; color: var(--text-muted); border: 1px solid var(--border); }

        .filter-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            align-items: end;
        }

        .input-group label {
            display: block;
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }

        .input {
            width: 100%;
            padding: 10px 12px;
            border-radius: 6px;
            border: 1px solid var(--border);
            font-family: inherit;
            font-size: 0.9rem;
            color: var(--text-main);
            background-color: #fff;
            transition: all 0.2s;
            height: 42px; /* Uniform height */
        }

        .input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
        }

        select.input {
            cursor: pointer;
            appearance: none;
            background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%2364748b' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e");
            background-position: right 0.75rem center;
            background-repeat: no-repeat;
            background-size: 1.25em 1.25em;
            padding-right: 2.5rem;
        }

        /* --- Buttons --- */
        button.btn-reset {
            background-color: var(--text-main);
            color: white;
            border: none;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
        }
        button.btn-reset:hover { background-color: #334155; }
        button.btn-reset:active { transform: translateY(1px); }

        /* --- Data Table --- */
        .table-card {
            background: var(--bg-card);
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            border: 1px solid var(--border);
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .table-container {
            overflow-x: auto;
            width: 100%;
            max-height: 75vh; /* Vertical scroll for massive lists */
        }

        table {
            width: 100%;
            border-collapse: separate; /* Allows sticky header */
            border-spacing: 0;
            min-width: 1200px;
        }

        thead {
            position: sticky;
            top: 0;
            z-index: 10;
            background: #f8fafc;
        }

        th {
            background: #f1f5f9;
            text-align: left;
            padding: 16px;
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }

        td {
            padding: 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
            color: var(--text-main);
            font-size: 0.9rem;
        }

        tbody tr { transition: background-color 0.15s ease; }
        tbody tr:hover { background-color: #f8fafc; }
        tbody tr:last-child td { border-bottom: none; }

        /* --- Column Styles --- */
        .font-mono { font-family: 'JetBrains Mono', monospace; font-size: 0.85em; }

        .cell-target { display: flex; flex-direction: column; gap: 4px; }
        .target-ip { font-weight: 600; color: var(--text-main); }
        .target-port { font-size: 0.8em; color: var(--text-muted); display: flex; align-items: center; gap: 4px; }
        
        .badge { 
            display: inline-flex; 
            align-items: center; 
            padding: 2px 8px; 
            border-radius: 6px; 
            font-weight: 600; 
            font-size: 0.75em;
            text-transform: uppercase;
            letter-spacing: 0.02em;
        }
        
        .badge-scheme { background: var(--border); color: var(--text-muted); }
        
        .badge-status { border-radius: 99px; padding: 4px 10px; }
        .status-2xx { background: var(--status-2xx-bg); color: var(--status-2xx-text); }
        .status-3xx { background: var(--status-3xx-bg); color: var(--status-3xx-text); }
        .status-4xx { background: var(--status-4xx-bg); color: var(--status-4xx-text); }
        .status-5xx { background: var(--status-5xx-bg); color: var(--status-5xx-text); }

        .cell-uri { max-width: 400px; word-break: break-all; }
        .uri-main { color: var(--primary); font-weight: 500; margin-bottom: 6px; display: block; text-decoration: none; }
        .uri-main:hover { text-decoration: underline; }
        
        .redirect-flow { 
            font-size: 0.85em; 
            color: var(--text-muted); 
            display: flex; 
            align-items: center; 
            gap: 6px; 
            margin-top: 4px;
            background: #f8fafc;
            padding: 4px 8px;
            border-radius: 4px;
            width: fit-content;
        }

        .server-tag {
            background: #f1f5f9;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            color: var(--text-main);
            border: 1px solid var(--border);
            display: inline-block;
        }

        .meta-info { font-size: 0.85em; color: var(--text-muted); line-height: 1.6; }

        /* --- Recon List --- */
        .recon-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 8px; }
        .recon-item { 
            font-size: 0.85em; 
            padding: 8px; 
            background: #f8fafc; 
            border-radius: 6px; 
            border: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        .recon-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px; }
        .recon-cat { color: var(--primary); font-weight: 700; font-size: 0.8em; text-transform: uppercase; }
        .recon-purpose { color: var(--text-muted); font-size: 0.8em; font-style: italic; margin-left: 8px; }
        .recon-key { color: var(--text-muted); font-family: 'JetBrains Mono', monospace; font-size: 0.9em; }
        .recon-val { color: var(--text-main); word-break: break-all; }

        .no-results { 
            padding: 60px; 
            text-align: center; 
            color: var(--text-muted); 
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 12px;
        }
        .no-results svg { width: 48px; height: 48px; opacity: 0.5; }

        /* Utilities */
        .text-empty { color: #cbd5e1; font-style: italic; }
    </style>
</head>
<body>

<div class="container">
    <div class="dashboard-header">
        <div class="header-top">
            <h1>Scan Results</h1>
            <div class="meta-tag">{{ len .Results }} Targets Found</div>
        </div>
        
        <div class="filter-grid">
            <div class="input-group">
                <label>Text Search</label>
                <input id="q" class="input" placeholder="Search URI, Title, Headers..." oninput="applyFilters()" />
            </div>

            <div class="input-group">
                <label>Scheme</label>
                <!-- Populated via JS for Uniqueness -->
                <select id="scheme" class="input" onchange="applyFilters()">
                    <option value="">All Schemes</option>
                </select>
            </div>

            <div class="input-group">
                <label>Port</label>
                <!-- Populated via JS for Uniqueness -->
                <select id="port" class="input" onchange="applyFilters()">
                    <option value="">All Ports</option>
                </select>
            </div>

            <div class="input-group">
                <label>Status Code</label>
                <select id="status" class="input" onchange="applyFilters()">
                    <option value="">All Statuses</option>
                    {{- range .StatusCodes }}
                    <option value="{{.}}">{{.}}</option>
                    {{- end }}
                </select>
            </div>

            <div class="input-group">
                <label>Server</label>
                <select id="server" class="input" onchange="applyFilters()">
                    <option value="">All Servers</option>
                    {{- range .Servers }}
                    <option value="{{.}}">{{.}}</option>
                    {{- end }}
                </select>
            </div>

            <div class="input-group">
                <button class="input btn-reset" onclick="resetFilters()">Reset Filters</button>
            </div>
        </div>
    </div>

    <div class="table-card">
        <div class="table-container">
            <table id="results">
                <thead>
                    <tr>
                        <th style="width: 140px;">IP Address</th>
                        <th style="width: 80px;">Port</th>
                        <th style="width: 80px;">Scheme</th>
                        <th>URI & Redirection</th>
                        <th>Page Title</th>
                        <th style="width: 100px;">Status</th>
                        <th>Server</th>
                        <th style="width: 150px;">Meta</th>
                        <th style="width: 350px;">Recon Data</th>
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
                    
                    <td class="font-mono">
                        <span class="target-ip">{{ $r.TargetData.IP }}</span>
                    </td>

                    <td class="font-mono">
                        <span style="color:var(--text-muted);">{{ $r.TargetData.Port }}</span>
                    </td>

                    <td>
                        <span class="badge badge-scheme">{{ $r.TargetData.Scheme }}</span>
                    </td>

                    <td class="cell-uri font-mono">
                        <a href="{{ $r.InitialURI }}" target="_blank" class="uri-main">{{ $r.InitialURI }}</a>
                        {{- if ne $r.RedirectURi "" }}
                        <div class="redirect-flow">
                            <span>↳</span> <span>{{ $r.RedirectURi }}</span>
                        </div>
                        {{- end }}
                    </td>

                    <td>
                        <div style="font-weight:500;">
                            {{ if ne $r.PageTitle "" }}
                                {{ $r.PageTitle }}
                            {{ else }}
                                <span class="text-empty">No Title</span>
                            {{ end }}
                        </div>
                    </td>

                    <td>
                        <span class="badge badge-status" data-status-val="{{ $r.StatusCode }}">{{ $r.StatusCode }}</span>
                    </td>

                    <td>
                        {{- if ne $r.Server "" }}
                        <span class="server-tag">{{ $r.Server }}</span>
                        {{- else }}
                        <span class="text-empty">—</span>
                        {{- end }}
                    </td>

                    <td class="meta-info">
                        <div>{{ $r.ContentType }}</div>
                        <div style="margin-top:4px;">Size: {{ $r.ContentLength }}</div>
                    </td>

                    <td>
                        {{- if gt (len $r.ReconInfo) 0 }}
                        <ul class="recon-list">
                        {{- range $r.ReconInfo }}
                        <li class="recon-item">
                            <div class="recon-header">
                                <div>
                                    <span class="recon-cat">{{ .CategoryName }}</span>
                                    <span class="recon-purpose">{{ .Purpose }}</span>
                                </div>
                            </div>
                            <div>
                                <span class="recon-key">{{ .HeaderName }}:</span>
                                <span class="recon-val">{{ .HeaderValue }}</span>
                            </div>
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
            <div>No matching results found</div>
            <button onclick="resetFilters()" style="color:var(--primary); background:none; border:none; cursor:pointer; text-decoration:underline;">Clear filters</button>
        </div>
    </div>
</div>

<script>
// 1. Populate Dropdowns Dynamically (Fixes Uniqueness Issue)
function populateDropdowns() {
    const rows = document.querySelectorAll('#results tbody tr');
    const schemes = new Set();
    const ports = new Set();

    // Collect unique values
    rows.forEach(row => {
        const s = row.getAttribute('data-scheme');
        const p = row.getAttribute('data-port');
        if (s) schemes.add(s);
        if (p) ports.add(p);
    });

    // Helper to add options
    const addOptions = (id, set, isNumeric) => {
        const select = document.getElementById(id);
        const array = Array.from(set);
        
        // Sort: Numbers numeric, Strings alphabetical
        if (isNumeric) {
            array.sort((a, b) => parseInt(a) - parseInt(b));
        } else {
            array.sort();
        }

        array.forEach(val => {
            const opt = document.createElement('option');
            opt.value = val;
            opt.textContent = val;
            select.appendChild(opt);
        });
    };

    addOptions('scheme', schemes, false);
    addOptions('port', ports, true);
}

// 2. Colorize status codes
function colorizeStatus() {
    document.querySelectorAll('.badge-status').forEach(el => {
        const code = parseInt(el.getAttribute('data-status-val'));
        if (code >= 200 && code < 300) el.classList.add('status-2xx');
        else if (code >= 300 && code < 400) el.classList.add('status-3xx');
        else if (code >= 400 && code < 500) el.classList.add('status-4xx');
        else if (code >= 500) el.classList.add('status-5xx');
    });
}

// 3. Filter Logic - Helpers
function normalize(s){ return s ? String(s).toLowerCase().trim() : ""; }

function applyFilters(){
    // Get values from inputs
    var q = normalize(document.getElementById('q').value);
    var scheme = normalize(document.getElementById('scheme').value);
    var port = normalize(document.getElementById('port').value);
    var status = normalize(document.getElementById('status').value);
    var server = normalize(document.getElementById('server').value);

    var rows = Array.from(document.querySelectorAll('#results tbody tr'));
    var shown = 0;

    rows.forEach(function(r){
        var text = normalize(r.textContent);
        
        // Data Attributes 
        var rowScheme = normalize(r.getAttribute('data-scheme'));
        var rowPort = normalize(r.getAttribute('data-port'));
        var rowStatus = normalize(r.getAttribute('data-status'));
        var rowServer = normalize(r.getAttribute('data-server'));

        // Check Matches
        var matchesQ = q === '' || text.indexOf(q) !== -1;
        var matchesScheme = scheme === '' || rowScheme === scheme;
        var matchesPort = port === '' || rowPort === port;
        var matchesStatus = status === '' || rowStatus === status;
        var matchesServer = server === '' || rowServer === server;

        if(matchesQ && matchesScheme && matchesPort && matchesStatus && matchesServer){
            r.style.display = '';
            shown++;
        } else { 
            r.style.display = 'none'; 
        }
    });
    
    document.getElementById('none').style.display = shown === 0 ? 'flex' : 'none';
    document.getElementById('results').style.display = shown === 0 ? 'none' : 'table';
}

function resetFilters(){ 
    document.querySelectorAll('input.input, select.input').forEach(i => i.value = '');
    applyFilters(); 
}

// Initialize
populateDropdowns();
colorizeStatus();
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

