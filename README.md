<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>
<body>

<h1>SocialCrawl — OSINT username &amp; alias exposure scanner</h1>

<p><strong>TL;DR:</strong> Async, OPSEC-aware username scanner with alias discovery, weighted exposure scoring, JSON/HTML output, and a slick terminal UX. Built to be a reusable module inside a larger OSINT program. fileciteturn1file0</p>

<blockquote>
  <p>This module is designed to plug into a broader OSINT pipeline. Use it to enumerate a username (and likely aliases) across many platforms, then score exposure for fast triage.</p>
</blockquote>

<hr />

<h2>What it does</h2>
<ol>
  <li><strong>Asynchronous scanning (httpx):</strong> fast checks across many sites.</li>
  <li><strong>External site list:</strong> bring your own <code>sites.json</code> with per-platform rules.</li>
  <li><strong>Alias discovery (Light Mode):</strong> generate candidate aliases and scan them.</li>
  <li><strong>Alias confidence &amp; multi-platform strength:</strong> HIGH/MEDIUM/LOW labels.</li>
  <li><strong>Weighted exposure score v2.0:</strong> category-aware scoring (social/dev/adult/crypto/other) and alias hits.</li>
  <li><strong>OPSEC pack:</strong> randomized User-Agent, proxy/Tor support, browser-like headers, jitter, stealth mode, and OPSEC summary.</li>
  <li><strong>Output choices:</strong> colorized console, <strong>--json</strong>, optional HTML report (light/dark).</li>
  <li><strong>Progress UX:</strong> green CRT-style progress bar + spinner while scanning.</li>
</ol>

<hr />

<h2>How SocialCrawl differs from <em>Sherlock</em></h2>
<ul>
  <li><strong>Alias intelligence:</strong> SocialCrawl can generate alias candidates and score them; Sherlock focuses mainly on exact-handle checks.</li>
  <li><strong>Scoring:</strong> Weighted exposure <strong>v2.0</strong> + alias-adjusted score provides an at-a-glance risk/exposure metric.</li>
  <li><strong>OPSEC-first:</strong> built-in stealth mode (headers, jitter, reduced concurrency), Tor/proxy, randomized UA, and OPSEC flags.</li>
  <li><strong>HTML report:</strong> modern, themed HTML with summary and alias sections.</li>
  <li><strong>Extensible config:</strong> first-class <code>sites.json</code> with per-site detection strategies.</li>
  <li><strong>Async by default:</strong> httpx-based concurrency for speed on large site lists.</li>
</ul>

<p>Sherlock remains great for broad username enumeration; SocialCrawl is aimed at <strong>investigation workflow</strong>: alias reasoning, exposure scoring, OPSEC ergonomics, and reportability. fileciteturn1file0</p>

<hr />

<h2>Features in detail</h2>

<h3>Site configuration</h3>
<ul>
  <li>JSON-driven (<code>name</code>, <code>url</code>, <code>error_type</code>, <code>valid_status</code>, <code>claimed_indicators</code>, <code>missing_indicators</code>, <code>headers</code>, <code>timeout</code>, <code>enabled</code>).</li>
  <li>Built-in defaults cover common platforms; your <code>sites.json</code> overrides/extends.</li>
</ul>

<h3>Alias discovery &amp; confidence</h3>
<ul>
  <li>Light Mode alias generation via <code>alias_engine.generate_aliases(username)</code>.</li>
  <li>Confidence combines edit distance, common alias patterns, and multi-platform strength. Labels: <strong>HIGH/MEDIUM/LOW</strong>.</li>
</ul>

<h3>Exposure scoring</h3>
<ul>
  <li>Basic v1: hit ratio across sites.</li>
  <li><strong>v2.0:</strong> category weights (social, dev, adult, crypto, other) + discounted alias hits → <strong>0–100</strong>.</li>
</ul>

<h3>OPSEC &amp; resilience</h3>
<ul>
  <li>Random UA, browser-like headers, jitter/sleep, reduced concurrency in <code>--stealth</code>.</li>
  <li>Proxy/Tor (<code>--proxy</code>, <code>--tor</code> socks5).</li>
  <li>Captcha/WAF/403/429 heuristics → OPSEC flags in output.</li>
</ul>

<h3>Outputs</h3>
<ul>
  <li><strong>Console:</strong> colorized sections (FOUND/NOT FOUND/ERRORS), OPSEC summary.</li>
  <li><strong>JSON:</strong> <code>--json</code> returns structured results + summary.</li>
  <li><strong>HTML:</strong> <code>--html-report</code> writes <code>./reports/&lt;username&gt;_report.html</code> with light/dark toggle.</li>
</ul>

<hr />

<h2>CLI usage</h2>
<pre><code># basic
python socialcrawl.py --username 

# with custom sites.json
python socialcrawl.py --username  --sites-json sites.json

# alias discovery (Light Mode)
python socialcrawl.py --username  --sites-json sites.json --aliases

# HTML report
python socialcrawl.py --username  --sites-json sites.json --aliases --html-report

# OPSEC: stealth + Tor
python socialcrawl.py --username  --stealth --tor
</code></pre>

<p><strong>JSON example:</strong></p>
<pre><code>python socialcrawl.py -u  --json &gt; .json
</code></pre>

<hr />

<h2>Linux requirements &amp; setup</h2>

<h3>OS &amp; Python</h3>
<ul>
  <li><strong>Linux (x86_64/ARM)</strong></li>
  <li><strong>Python 3.8+</strong> (tested with 3.10/3.11)</li>
</ul>

<h3>Network</h3>
<ul>
  <li>Outbound <strong>HTTP/HTTPS</strong> to target platforms.</li>
  <li>Optional <strong>Tor</strong> at <code>socks5://127.0.0.1:9050</code> if <code>--tor</code> is used.</li>
</ul>

<h3>System packages</h3>
<ul>
  <li>None required for default HTTP flow.</li>
  <li>For Tor routing, run a local Tor client (e.g., <code>sudo apt install tor</code>).</li>
</ul>

<h3>Python packages</h3>
<p>Install via <code>pip</code>:</p>
<pre><code>pip install -r requirements_socialcrawl.txt
</code></pre>
<ul>
  <li><code>httpx[socks]</code> — async HTTP client with SOCKS support (for <code>--tor</code>/<code>--proxy</code>).</li>
</ul>
<p><em>Local module:</em> <code>alias_engine.py</code> must be present on <code>PYTHONPATH</code> (provides <code>generate_aliases</code>). If missing, <code>--aliases</code> features will not run.</p>

<hr />

<h2>Integration in a larger OSINT program</h2>
<ul>
  <li><strong>Library use:</strong> import <code>enumerate_username</code>, <code>summarize_results</code>, <code>compute_weighted_exposure_v2</code>, <code>generate_html_report</code>.</li>
  <li><strong>Pipelining:</strong> call CLI from orchestration, parse JSON, or import functions directly.</li>
  <li><strong>Extensibility:</strong> expand <code>sites.json</code>, tweak weights/categories, or swap alias generator.</li>
</ul>

<hr />

<h2>Limitations / notes</h2>
<ul>
  <li>Rate-limits, WAFs, and captchas may cause inconclusive results; use <code>--stealth</code>/proxies.</li>
  <li>Alias engine is “Light Mode” and may surface noisy candidates; confidence labels help triage.</li>
  <li>Platform HTML and anti-bot behavior change frequently; keep <code>sites.json</code> current.</li>
</ul>

<hr />

<h2>License</h2>
<p>Non-Commercial Software License (NCSL) v1.0 (see <code>LICENSE</code>).</p>

</body>
</html>
