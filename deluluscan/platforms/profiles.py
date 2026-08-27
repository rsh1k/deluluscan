"""Platform intelligence — what the target *is*, and what that means for testing.

A profile teaches the scanner a platform's architecture: how to fingerprint it,
where its API lives and what shape it takes, its authentication model, its
user-enumeration and version-disclosure surfaces, and the vuln classes that
matter most for it. This is how the tool "understands the system" instead of
blindly probing paths.

Grounded in public research (OWASP WSTG fingerprinting; WordPress REST API user
enumeration via /wp-json/wp/v2/users; Drupal JSON:API entity/user exposure;
Joomla web-services API; cloud-hosting response headers). Detection only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Signal:
    """One fingerprint check. kind ∈ path|header|body|meta-generator|api-json."""
    kind: str
    key: str = ""                     # header name, or path to GET
    pattern: str = ""                 # regex matched against the relevant text
    weight: float = 1.0
    statuses: tuple = ()              # for kind=path: acceptable statuses


@dataclass
class PlatformProfile:
    name: str
    category: str                     # cms | framework | hosting | api-gateway
    signals: list = field(default_factory=list)
    api_base: str = ""                # where the platform's API lives
    api_style: str = ""               # REST | JSON:API | GraphQL | RPC
    api_discovery: str = ""           # path that lists the API surface
    auth_methods: tuple = ()          # cookie | basic | bearer | api-key | jwt | oauth | token
    login_path: str = ""
    users_endpoint: str = ""          # unauth user-enumeration surface, if any
    version_path: str = ""            # path that discloses version
    version_regex: str = ""
    sensitive_paths: tuple = ()       # high-value surfaces a human should check
    exposed_checks: tuple = ()        # (path, severity_if_reachable, note) probed live
    relevant_classes: tuple = ()      # vuln classes to prioritize for this platform
    remediation: str = ""


PROFILES: list[PlatformProfile] = [
    # ---- WordPress -------------------------------------------------------
    PlatformProfile(
        name="WordPress", category="cms",
        signals=[
            Signal("path", "/wp-login.php", statuses=(200, 302, 301), weight=2),
            Signal("api-json", "/wp-json/", pattern=r'(?i)"namespaces"|wp/v2', weight=3),
            Signal("header", "x-pingback", pattern=r"xmlrpc\.php", weight=2),
            Signal("body", "/", pattern=r"/wp-content/|/wp-includes/", weight=1.5),
            Signal("meta-generator", "/", pattern=r"(?i)WordPress", weight=2),
        ],
        api_base="/wp-json", api_style="REST", api_discovery="/wp-json/",
        auth_methods=("cookie", "basic", "jwt"), login_path="/wp-login.php",
        users_endpoint="/wp-json/wp/v2/users",
        version_path="/wp-json/", version_regex=r'(?i)"description"[^}]*WordPress\s*([0-9.]+)',
        sensitive_paths=("/xmlrpc.php", "/wp-admin/", "/wp-json/wp/v2/users",
                         "/wp-content/debug.log", "/wp-config.php.bak"),
        exposed_checks=(("/xmlrpc.php", "medium",
                         "XML-RPC endpoint — pingback SSRF and system.multicall "
                         "amplified credential brute-force."),
                        ("/wp-content/debug.log", "high",
                         "WordPress debug log may leak paths, queries, and secrets.")),
        relevant_classes=("info_leak", "authz", "xss", "sqli", "supply_chain"),
        remediation="Disable REST user enumeration + xmlrpc.php; require permission_callback "
                    "on custom routes; keep core/plugins patched."),
    # ---- Drupal ----------------------------------------------------------
    PlatformProfile(
        name="Drupal", category="cms",
        signals=[
            Signal("path", "/CHANGELOG.txt", pattern=r"(?i)Drupal", statuses=(200,), weight=3),
            Signal("api-json", "/jsonapi", pattern=r'(?i)"jsonapi"|"json:api"', weight=3),
            Signal("header", "x-generator", pattern=r"(?i)Drupal", weight=2),
            Signal("body", "/", pattern=r"/sites/default/|/core/misc/", weight=1.5),
            Signal("meta-generator", "/", pattern=r"(?i)Drupal", weight=2),
            Signal("path", "/user/login", statuses=(200, 303), weight=1),
        ],
        api_base="/jsonapi", api_style="JSON:API", api_discovery="/jsonapi",
        auth_methods=("cookie", "basic", "api-key", "jwt"), login_path="/user/login",
        users_endpoint="/jsonapi/user/user",
        version_path="/CHANGELOG.txt", version_regex=r"(?i)Drupal\s*([0-9.]+)",
        sensitive_paths=("/jsonapi/user/user", "/admin", "/core/install.php",
                         "/CHANGELOG.txt", "/sites/default/settings.php"),
        relevant_classes=("info_leak", "authz", "error_handling", "supply_chain"),
        remediation="Disable/lock the JSON:API user resource; restrict entity access; "
                    "remove CHANGELOG.txt; disable verbose error backtraces."),
    # ---- Joomla ----------------------------------------------------------
    PlatformProfile(
        name="Joomla", category="cms",
        signals=[
            Signal("path", "/administrator/", statuses=(200, 303), weight=2),
            Signal("meta-generator", "/", pattern=r"(?i)Joomla", weight=3),
            Signal("body", "/", pattern=r"/media/system/|/templates/system/", weight=1.5),
            Signal("api-json", "/api/index.php/v1/", pattern=r'(?i)"data"|jsonapi', weight=2),
        ],
        api_base="/api/index.php/v1", api_style="REST", api_discovery="/api/index.php/v1/",
        auth_methods=("cookie", "token"), login_path="/administrator/",
        version_path="/administrator/manifests/files/joomla.xml",
        version_regex=r"<version>([0-9.]+)</version>",
        sensitive_paths=("/administrator/", "/configuration.php.bak",
                         "/language/en-GB/en-GB.xml"),
        exposed_checks=(("/administrator/", "info",
                         "Administrator console reachable from the network."),),
        relevant_classes=("info_leak", "authz", "supply_chain"),
        remediation="Restrict /administrator/; remove version manifests; patch components."),
    # ---- Ghost -----------------------------------------------------------
    PlatformProfile(
        name="Ghost", category="cms",
        signals=[
            Signal("api-json", "/ghost/api/content/settings/", pattern=r'(?i)ghost|"settings"', weight=3),
            Signal("path", "/ghost/", statuses=(200, 302), weight=2),
            Signal("meta-generator", "/", pattern=r"(?i)Ghost\s*[0-9.]", weight=2),
        ],
        api_base="/ghost/api", api_style="REST", api_discovery="/ghost/api/content/",
        auth_methods=("bearer", "api-key"), login_path="/ghost/",
        sensitive_paths=("/ghost/", "/ghost/api/admin/"),
        relevant_classes=("authz", "info_leak")),
    # ---- Cloud hosting (response-header signals) -------------------------
    PlatformProfile(
        name="AWS (S3/CloudFront)", category="hosting",
        signals=[
            Signal("header", "server", pattern=r"(?i)AmazonS3", weight=3),
            Signal("header", "x-amz-request-id", pattern=r".+", weight=3),
            Signal("header", "via", pattern=r"(?i)cloudfront", weight=2),
            Signal("header", "x-cache", pattern=r"(?i)cloudfront", weight=1),
        ],
        relevant_classes=("misconfig", "info_leak"),
        remediation="Review S3 bucket ACL/policy; see the cloud (CSPM) module for posture."),
    PlatformProfile(
        name="Google Cloud (GCS/GCLB)", category="hosting",
        signals=[
            Signal("header", "server", pattern=r"(?i)UploadServer|GSE", weight=2),
            Signal("header", "x-goog-generation", pattern=r".+", weight=3),
            Signal("header", "via", pattern=r"(?i)google", weight=1),
        ],
        relevant_classes=("misconfig", "info_leak")),
    PlatformProfile(
        name="Microsoft Azure", category="hosting",
        signals=[
            Signal("header", "server", pattern=r"(?i)Windows-Azure|Microsoft-IIS", weight=2),
            Signal("header", "x-azure-ref", pattern=r".+", weight=3),
            Signal("header", "x-ms-request-id", pattern=r".+", weight=2),
        ],
        relevant_classes=("misconfig", "info_leak")),

    # ---- Web frameworks --------------------------------------------------
    PlatformProfile(
        name="Laravel (PHP)", category="framework",
        signals=[
            Signal("body", "/", pattern=r"(?i)laravel", weight=1),
            Signal("header", "set-cookie", pattern=r"laravel_session|XSRF-TOKEN", weight=3),
        ],
        auth_methods=("cookie", "bearer"),
        version_path="/", version_regex=r"(?i)Laravel v?([0-9.]+)",
        sensitive_paths=("/.env", "/telescope", "/_ignition/health-check", "/storage/logs/laravel.log"),
        exposed_checks=(("/.env", "critical", "Laravel .env may expose DB creds, APP_KEY, mail/API secrets."),
                        ("/telescope", "high", "Laravel Telescope debug UI exposes requests, queries, and payloads."),
                        ("/_ignition/health-check", "high", "Ignition debug endpoint (CVE-2021-3129 RCE surface).")),
        relevant_classes=("info_leak", "misconfig", "supply_chain"),
        remediation="Block /.env and debug tooling in production; rotate any leaked APP_KEY/secrets."),
    PlatformProfile(
        name="Django (Python)", category="framework",
        signals=[
            Signal("header", "set-cookie", pattern=r"csrftoken|sessionid", weight=2),
            Signal("body", "/admin/", pattern=r"(?i)Django administration", weight=3),
        ],
        login_path="/admin/", auth_methods=("cookie",),
        sensitive_paths=("/admin/", "/static/admin/", "/__debug__/"),
        exposed_checks=(("/admin/", "info", "Django admin login reachable."),
                        ("/__debug__/", "high", "django-debug-toolbar is enabled (DEBUG=True leaks settings/SQL).")),
        relevant_classes=("info_leak", "authz", "misconfig"),
        remediation="Set DEBUG=False in production; restrict /admin/; never expose debug toolbar."),
    PlatformProfile(
        name="Ruby on Rails", category="framework",
        signals=[
            Signal("header", "x-runtime", pattern=r".+", weight=1),
            Signal("header", "set-cookie", pattern=r"_session_id|_rails", weight=2),
            Signal("body", "/", pattern=r"(?i)Ruby on Rails|Rails\.application", weight=2),
        ],
        sensitive_paths=("/rails/info/routes", "/rails/info/properties"),
        exposed_checks=(("/rails/info/routes", "medium", "Rails route map exposed (dev mode leaks the full API surface)."),),
        relevant_classes=("info_leak", "misconfig", "supply_chain"),
        remediation="Ensure RAILS_ENV=production; never expose /rails/info in production."),
    PlatformProfile(
        name="Express (Node.js)", category="framework",
        signals=[Signal("header", "x-powered-by", pattern=r"(?i)express", weight=3)],
        relevant_classes=("misconfig", "info_leak"),
        remediation="Disable x-powered-by (helmet / app.disable('x-powered-by'))."),
    PlatformProfile(
        name="Spring Boot (Java)", category="framework",
        signals=[
            Signal("api-json", "/actuator", pattern=r'(?i)"_links"|health|actuator', weight=3),
            Signal("api-json", "/actuator/health", pattern=r'(?i)"status"\s*:\s*"UP"', weight=3),
            Signal("body", "/", pattern=r"(?i)Whitelabel Error Page", weight=2),
        ],
        api_base="/actuator", api_style="REST", api_discovery="/actuator",
        version_path="/actuator/info", version_regex=r'(?i)"version"\s*:\s*"([0-9.]+)"',
        sensitive_paths=("/actuator/env", "/actuator/heapdump", "/actuator/mappings", "/actuator/beans"),
        exposed_checks=(("/actuator/env", "high", "Spring actuator /env leaks config + often decrypted secrets."),
                        ("/actuator/heapdump", "critical", "Actuator heapdump downloads full process memory (tokens, creds)."),
                        ("/actuator/mappings", "medium", "Actuator mappings enumerate every route.")),
        relevant_classes=("info_leak", "misconfig", "memory_disclosure"),
        remediation="Expose only /actuator/health; secure the rest behind auth; never expose heapdump/env."),
    PlatformProfile(
        name="Apache Tomcat", category="framework",
        signals=[
            Signal("header", "server", pattern=r"(?i)Apache-Coyote|Tomcat", weight=2),
            Signal("body", "/", pattern=r"(?i)Apache Tomcat", weight=2),
        ],
        version_path="/", version_regex=r"(?i)Apache Tomcat/([0-9.]+)",
        sensitive_paths=("/manager/html", "/host-manager/html", "/manager/status"),
        exposed_checks=(("/manager/html", "high", "Tomcat Manager (WAR deploy = RCE) reachable."),
                        ("/host-manager/html", "high", "Tomcat Host Manager reachable.")),
        relevant_classes=("authz", "supply_chain", "misconfig"),
        remediation="Restrict /manager and /host-manager to admin networks; use strong creds."),

    # ---- E-commerce ------------------------------------------------------
    PlatformProfile(
        name="Magento", category="cms",
        signals=[
            Signal("header", "set-cookie", pattern=r"X-Magento-Vary|frontend=", weight=2),
            Signal("body", "/", pattern=r"(?i)/static/version|Mage\.Cookies|Magento", weight=2),
            Signal("path", "/magento_version", statuses=(200,), weight=3),
        ],
        version_path="/magento_version", version_regex=r"(?i)Magento/([0-9.]+)",
        sensitive_paths=("/downloader/", "/app/etc/local.xml", "/rest/V1/", "/admin"),
        exposed_checks=(("/app/etc/local.xml", "critical", "Magento local.xml leaks DB creds + crypt key."),
                        ("/downloader/", "high", "Magento Connect downloader reachable (historic RCE surface).")),
        relevant_classes=("info_leak", "authz", "supply_chain"),
        remediation="Block config/downloader paths; patch to a supported Magento/Adobe Commerce release."),
    PlatformProfile(
        name="Shopify", category="hosting",
        signals=[
            Signal("header", "x-shopid", pattern=r".+", weight=3),
            Signal("header", "x-shopify-stage", pattern=r".+", weight=3),
            Signal("header", "x-sorting-hat-shopid", pattern=r".+", weight=2),
        ],
        relevant_classes=("info_leak", "business_logic")),

    # ---- DevOps / infra consoles ----------------------------------------
    PlatformProfile(
        name="Jenkins", category="framework",
        signals=[
            Signal("header", "x-jenkins", pattern=r".+", weight=3),
            Signal("header", "x-jenkins-session", pattern=r".+", weight=2),
            Signal("body", "/", pattern=r"(?i)Jenkins ver\.|Dashboard \[Jenkins\]", weight=2),
        ],
        version_path="/", version_regex=r"(?i)Jenkins ver\.?\s*([0-9.]+)",
        login_path="/login", auth_methods=("cookie", "basic", "api-key"),
        sensitive_paths=("/script", "/manage", "/asynchPeople/", "/api/json"),
        exposed_checks=(("/script", "critical", "Jenkins Groovy script console = unauthenticated RCE if open."),
                        ("/asynchPeople/", "medium", "Jenkins user enumeration surface.")),
        relevant_classes=("authz", "info_leak", "supply_chain"),
        remediation="Require auth globally; lock /script to admins; disable anonymous read."),
    PlatformProfile(
        name="GitLab", category="framework",
        signals=[
            Signal("header", "set-cookie", pattern=r"_gitlab_session", weight=3),
            Signal("body", "/users/sign_in", pattern=r"(?i)GitLab", weight=2),
            Signal("api-json", "/api/v4/version", pattern=r'(?i)"version"', weight=2),
        ],
        api_base="/api/v4", api_style="REST", login_path="/users/sign_in",
        auth_methods=("cookie", "bearer", "api-key"),
        sensitive_paths=("/api/v4/projects", "/explore", "/users/sign_up"),
        exposed_checks=(("/explore", "info", "GitLab public project explore reachable."),
                        ("/users/sign_up", "low", "Open registration may allow unauthorized accounts.")),
        relevant_classes=("authz", "info_leak", "supply_chain"),
        remediation="Disable open sign-up if unintended; keep GitLab patched (frequent critical CVEs)."),
    PlatformProfile(
        name="Grafana", category="framework",
        signals=[
            Signal("api-json", "/api/health", pattern=r'(?i)"database"\s*:\s*"ok"', weight=3),
            Signal("body", "/login", pattern=r"(?i)Grafana", weight=2),
            Signal("header", "set-cookie", pattern=r"grafana_session", weight=2),
        ],
        api_base="/api", login_path="/login", auth_methods=("cookie", "bearer", "basic"),
        version_path="/api/health", version_regex=r'(?i)"version"\s*:\s*"([0-9.]+)"',
        sensitive_paths=("/api/datasources", "/public/", "/api/admin/settings"),
        exposed_checks=(("/api/datasources", "high", "Grafana datasources API (CVE-2021-43798 path-traversal surface)."),),
        relevant_classes=("authz", "info_leak", "ssrf"),
        remediation="Require auth; disable anonymous org; patch (path-traversal + SSRF history)."),
    PlatformProfile(
        name="Kibana", category="framework",
        signals=[
            Signal("header", "kbn-name", pattern=r".+", weight=3),
            Signal("api-json", "/api/status", pattern=r'(?i)"kibana"|"status"', weight=2),
            Signal("body", "/", pattern=r"(?i)kbn-injected-metadata|Kibana", weight=1),
        ],
        api_base="/api", version_path="/api/status", version_regex=r'(?i)"number"\s*:\s*"([0-9.]+)"',
        sensitive_paths=("/app/dev_tools", "/api/console/proxy"),
        exposed_checks=(("/api/console/proxy", "high", "Kibana console proxy can reach Elasticsearch unauthenticated."),),
        relevant_classes=("authz", "info_leak"),
        remediation="Put Kibana behind auth; never expose it or Elasticsearch to untrusted networks."),
    PlatformProfile(
        name="phpMyAdmin", category="framework",
        signals=[
            Signal("body", "/", pattern=r"(?i)phpMyAdmin", weight=2),
            Signal("header", "set-cookie", pattern=r"phpMyAdmin|pmaAuth", weight=3),
        ],
        login_path="/", sensitive_paths=("/phpmyadmin/", "/pma/", "/index.php"),
        exposed_checks=(("/phpmyadmin/", "high", "phpMyAdmin reachable — direct DB admin surface, brute-force/CVE target."),),
        relevant_classes=("authz", "sqli", "supply_chain"),
        remediation="Restrict phpMyAdmin to admin networks; require strong auth; keep patched."),
    PlatformProfile(
        name="Atlassian (Jira/Confluence)", category="framework",
        signals=[
            Signal("header", "x-ausername", pattern=r".+", weight=3),
            Signal("body", "/", pattern=r"(?i)Atlassian|JIRA|Confluence", weight=2),
        ],
        sensitive_paths=("/status", "/rest/api/2/", "/secure/Dashboard.jspa"),
        exposed_checks=(("/rest/api/2/dashboard", "medium", "Jira REST reachable — unauth data exposure history."),),
        relevant_classes=("authz", "info_leak", "supply_chain", "ssti"),
        remediation="Patch aggressively (Confluence OGNL/SSTI + Jira auth-bypass CVEs); restrict REST."),

    # ---- Data stores / control planes (usually via port scan, but HTTP-ish)
    PlatformProfile(
        name="Elasticsearch", category="api-gateway",
        signals=[
            Signal("api-json", "/", pattern=r'(?i)"cluster_name"|"lucene_version"|You Know, for Search', weight=3),
            Signal("api-json", "/_cat/indices", pattern=r".+", weight=1),
        ],
        api_base="/", api_style="REST",
        version_path="/", version_regex=r'(?i)"number"\s*:\s*"([0-9.]+)"',
        sensitive_paths=("/_cat/indices", "/_search", "/_cluster/health", "/_nodes"),
        exposed_checks=(("/_cat/indices", "critical", "Elasticsearch indices listable unauthenticated — full data exposure."),
                        ("/_nodes", "high", "Elasticsearch node info leaks internal topology/plugins.")),
        relevant_classes=("authz", "info_leak"),
        remediation="Never expose Elasticsearch directly; enable security (auth+TLS); firewall 9200/9300."),
    PlatformProfile(
        name="Kubernetes API", category="api-gateway",
        signals=[
            Signal("api-json", "/version", pattern=r'(?i)"gitVersion"|"major"', weight=3),
            Signal("api-json", "/api", pattern=r'(?i)"versions"\s*:\s*\[', weight=2),
        ],
        api_base="/api", api_style="REST", auth_methods=("bearer", "token"),
        version_path="/version", version_regex=r'(?i)"gitVersion"\s*:\s*"v?([0-9.]+)',
        sensitive_paths=("/api/v1/secrets", "/api/v1/pods", "/apis"),
        exposed_checks=(("/api/v1/namespaces/default/pods", "critical",
                         "Kubernetes API answers unauthenticated (anonymous-auth enabled) — cluster takeover."),),
        relevant_classes=("authz", "info_leak", "misconfig"),
        remediation="Disable --anonymous-auth; enforce RBAC; never expose the API server publicly."),
]


def profile_by_name(name: str) -> Optional[PlatformProfile]:
    return next((p for p in PROFILES if p.name == name), None)
