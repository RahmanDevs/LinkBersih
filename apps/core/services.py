import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

import requests
import whois

from bs4 import BeautifulSoup
from django.core.cache import cache
from Levenshtein import distance as levenshtein_distance

from langchain_community.llms import HuggingFacePipeline
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool

from transformers import (
    AutoModelForSeq2SeqLM,
    AutoTokenizer,
    pipeline,
)

from apps.logger.models import ScanLog


# WHOIS
@tool
def check_whois_domain(domain: str) -> str:
    """Check domain age and creation date via WHOIS query."""
    try:
        w = whois.whois(domain)

        creation_date = (
            w.get("creation_date")
            if isinstance(w, dict)
            else getattr(w, "creation_date", None)
        )

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(creation_date, datetime):
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            age_days = (
                datetime.now(timezone.utc) - creation_date
            ).days

            return f"Domain age: {age_days} days"

        return "Domain age not available"

    except Exception as e:
        return f"WHOIS error: {str(e)}"


class PhishingDetectorService:

    # Configuration
    LLM_MODEL_NAME = "google/flan-t5-base"
    _llm_chain = None

    DOMAIN_WEIGHT = 0.40
    TRANSIT_WEIGHT = 0.30
    STRING_WEIGHT = 0.15
    LLM_WEIGHT = 0.15

    # Updated thresholds based on confidence score percentage
    SAFE_THRESHOLD = 0.80      # 80%-100%: AMAN
    SUSPICIOUS_THRESHOLD = 0.50  # 50%-79%: MENCURIGAKAN
    PHISHING_THRESHOLD = 0.0    # 0%-49%: BERBAHAYA/PHISHING

    SUSPICIOUS_TLDS = {
        "tk",
        "gq",
        "ml",
        "cf",
        "ga",
        "xyz",
        "top",
        "club",
        "online",
        "site",
        "vip",
        "work",
        "icu",
    }

    FREE_HOSTING_DOMAINS = {
        "pages.dev",
        "workers.dev",
        "vercel.app",
        "netlify.app",
        "github.io",
        "firebaseapp.com",
        "web.app",
    }

    URL_SHORTENERS = {
        "bit.ly",
        "goo.gl",
        "tinyurl.com",
        "ow.ly",
        "t.co",
        "is.gd",
        "rb.gy",
    }

    SUSPICIOUS_KEYWORDS = {
        "login",
        "verify",
        "verification",
        "update",
        "account",
        "secure",
        "security",
        "banking",
        "signin",
        "sign-in",
        "confirm",
        "confirmation",
        "claim",
        "bonus",
        "reward",
        "vip",
        "m4xw1n",
        "maxwin",
        "slot",
        "gacor",
        "deposit",
        "withdraw",
        "wallet",
    }

    COMMON_SUBDOMAINS = {
        "www",
        "mail",
        "webmail",
        "ftp",
        "api",
        "cdn",
        "static",
        "blog",
        "docs",
        "app",
        "dev",
        "staging",
    }

    # Whitelist - Domain yang dianggap AMAN (hanya domain resmi)
    WHITELIST_DOMAINS = {
        # Tech Giants
        "google.com",
        "google.co.id",
        "facebook.com",
        "instagram.com",
        "youtube.com",
        "whatsapp.com",
        "telegram.org",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "github.com",
        "gitlab.com",
        "stackoverflow.com",
        "wikipedia.org",
        "reddit.com",
        "tiktok.com",
        "snapchat.com",
        "pinterest.com",
        "medium.com",
        "substack.com",

        # E-Commerce Indonesia
        "tokopedia.com",
        "shopee.co.id",
        "shopee.com",
        "lazada.co.id",
        "bukalapak.com",
        "blibli.com",
        "bhinneka.com",
        "jdid.com",

        # E-Commerce Global
        "amazon.com",
        "amazon.co.id",
        "ebay.com",
        "aliexpress.com",
        "wish.com",

        # Streaming & Entertainment
        "netflix.com",
        "spotify.com",
        "disneyplus.com",
        "primevideo.com",
        "hulu.com",
        "viu.com",
        "wetv.vip",
        " Vidio.com",

        # Payment & Fintech
        "paypal.com",
        "stripe.com",
        "wise.com",
        "dana.id",
        "ovo.id",
        "gopay.co.id",
        "linkaja.id",
        "ovo.com",
        "dana.com",
        "gopay.com",
        "qris.id",

        # Bank Indonesia
        "bca.co.id",
        "bca.com",
        "mandiri.co.id",
        "mandiri.com",
        "bni.co.id",
        "bni.com",
        "bri.co.id",
        "bri.com",
        "btn.co.id",
        "btn.com",
        "danamon.co.id",
        "cimb Niaga.com",
        "paninbank.co.id",
        "megatama.co.id",
        "bukopin.co.id",
        "sinarmas.com",
        "bsii.co.id",
        "muamalat.co.id",
        "btps.co.id",
        "bpd.co.id",

        # Digital Bank
        "jenius.com",
        "jago.com",
        "neobank.co.id",
        "blu.bca.co.id",
        "Bank Jago",
        "tyme.com",
        "Sea Bank",
        "seabank.co.id",

        # Ride Hailing & Delivery
        "grab.com",
        "grab.co.id",
        "gojek.com",
        "gojek.co.id",
        "traveloka.com",
        "traveloka.co.id",
        "airAsia.com",
        "tiket.com",
        "redDoorz.com",

        # Telco
        "telkomsel.com",
        "indosatooredoo.com",
        "xl.co.id",
        "smartfren.com",
        "tri.co.id",
        "axis.co.id",

        # Government
        "go.id",
        "kemendikbud.go.id",
        "kemenkeu.go.id",
        "kemenkes.go.id",
        "kemendag.go.id",
        "kemenkop.go.id",
        "bps.go.id",
        "dukcapil.go.id",
        "pajak.go.id",
        "beacukai.go.id",
        "bpjs-kesehatan.go.id",
        "bpjs-ketenagakerjaan.go.id",
        "elev.ee",
        "jdih.go.id",
        "jakarta.go.id",
        "surabaya.go.id",
        "bandung.go.id",

        # Education
        "ac.id",
        "sch.id",
        "or.id",
        "id",
        "ui.ac.id",
        "ugm.ac.id",
        "itb.ac.id",
        "ipb.ac.id",
        "undip.ac.id",
        "uns.ac.id",
        "unair.ac.id",
        "ub.ac.id",
        "ugm.ac.id",

        # Tech & Cloud
        "microsoft.com",
        "apple.com",
        "cloudflare.com",
        "aws.amazon.com",
        "cloud.google.com",
        "azure.com",
        "digitalocean.com",
        "heroku.com",
        "vercel.com",
        "netlify.com",
        "github.io",

        # News & Media
        "kompas.com",
        "detik.com",
        "liputan6.com",
        "cnnindonesia.com",
        "cnbcindonesia.com",
        "tempo.co",
        "tirto.id",
        "jakartaglobe.id",
        "thejakartapost.com",
        "jakartaglobe.id",
        "bbc.com",
        "bbc.co.uk",
        "cnn.com",
        "reuters.com",
        "apnews.com",

        # Indonesian Companies
        "emiten.co.id",
        "idx.co.id",
        "bi.go.id",
        "kse.co.id",
        "asetku.co.id",

        # Misc Trusted
        "speedtest.net",
        "fast.com",
        "whatismyipaddress.com",
        "who.is",
        "whois.icann.org",
    }

    # Keyword yang AMAN jika muncul di SUBDOMAIN (bukan di seluruh URL)
    SAFE_SUBDOMAIN_KEYWORDS = {
        "mail",
        "webmail",
        "portal",
        "sso",
        "auth",
        "login",
        "account",
        "my",
        "app",
        "dev",
        "staging",
        "test",
        "demo",
        "beta",
        "alpha",
    }

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    # Target Brands
    @classmethod
    def get_target_brands(cls) -> List[str]:
        brands = cache.get("DYNAMIC_TARGET_BRANDS")

        if not brands:
            brands = [
                "google",
                "facebook",
                "instagram",
                "paypal",
                "apple",
                "microsoft",
                "bca",
                "tokopedia",
                "shopee",
                "lazada",
                "grab",
                "gopay",
                "ovo",
                "dana",
                "linkaja",
                "jenius",
                "mandiri",
                "bni",
                "bri",
                "btn",
                "amazon",
                "netflix",
                "spotify",
                "whatsapp",
                "telegram",
                "twitter",
                "linkedin",
                "youtube",
                "tiktok",
                "reddit",
            ]

            cache.set(
                "DYNAMIC_TARGET_BRANDS",
                brands,
                timeout=86400,
            )

        return brands

    # URL Helpers
    @staticmethod
    def normalize_url(url: str) -> str:
        url = url.strip()

        if not url:
            raise ValueError("URL cannot be empty.")

        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "https://" + url

        parsed = urlparse(url)

        if not parsed.hostname:
            raise ValueError("Invalid URL or hostname.")

        return url

    @staticmethod
    def extract_hostname(url: str) -> str:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()

    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0

        length = len(text)

        entropy = -sum(
            (count / length) * math.log2(count / length)
            for char in set(text)
            if (count := text.count(char)) > 0
        )

        return round(entropy, 2)

    @classmethod
    def is_whitelisted(cls, url: str) -> bool:
        """Check if URL domain is in whitelist (hanya check domain, bukan keyword)."""
        hostname = cls.extract_hostname(url)
        if not hostname:
            return False

        parts = hostname.split(".")
        hostname_lower = hostname.lower()

        # 1. Check exact hostname match (contoh: "google.com")
        if hostname_lower in cls.WHITELIST_DOMAINS:
            return True

        # 2. Check registered domain (last 2 parts, contoh: "google.com" dari "www.google.com")
        if len(parts) >= 2:
            registered_domain = ".".join(parts[-2:])
            if registered_domain in cls.WHITELIST_DOMAINS:
                return True

        # 3. Check if hostname END WITHS any whitelisted domain (contoh: "mail.google.com" ends with "google.com")
        for domain in cls.WHITELIST_DOMAINS:
            if hostname_lower.endswith("." + domain) or hostname_lower == domain:
                return True

        return False

    # Domain Analysis
    @classmethod
    def analyze_domain(cls, url: str) -> Dict[str, Any]:
        hostname = cls.extract_hostname(url)

        if not hostname:
            return {
                "domain_confidence": 1.0,
                "reasons": ["Invalid or missing hostname"],
                "indicators": {
                    "invalid_hostname": True,
                    "raw_ip": False,
                    "free_hosting": False,
                    "brand_impersonation": False,
                    "suspicious_subdomain": False,
                    "high_entropy": False,
                    "new_domain": False,
                    "recent_domain": False,
                    "suspicious_hostname": False,
                },
                "entropy": 0.0,
                "subdomain_depth": 0,
                "is_whitelisted": False,
            }

        # Check whitelist first
        if cls.is_whitelisted(url):
            return {
                "domain_confidence": 0.0,
                "reasons": ["Domain is whitelisted as safe"],
                "indicators": {
                    "invalid_hostname": False,
                    "raw_ip": False,
                    "free_hosting": False,
                    "brand_impersonation": False,
                    "suspicious_subdomain": False,
                    "high_entropy": False,
                    "new_domain": False,
                    "recent_domain": False,
                    "suspicious_hostname": False,
                    "whitelisted": True,
                },
                "entropy": 0.0,
                "subdomain_depth": 0,
                "is_whitelisted": True,
            }

        score = 0.0
        reasons = []

        indicators = {
            "invalid_hostname": False,
            "raw_ip": False,
            "free_hosting": False,
            "brand_impersonation": False,
            "suspicious_subdomain": False,
            "high_entropy": False,
            "new_domain": False,
            "recent_domain": False,
            "suspicious_hostname": False,
        }

        # Raw IP
        if re.match(
            r"^\d{1,3}(\.\d{1,3}){3}$",
            hostname,
        ):
            indicators["raw_ip"] = True
            indicators["suspicious_hostname"] = True

            score += 0.50

            reasons.append(
                "Raw IP address used instead of a domain name"
            )

        # Free Hosting
        matched_free_host = None

        for free_host in cls.FREE_HOSTING_DOMAINS:
            if (
                hostname == free_host
                or hostname.endswith("." + free_host)
            ):
                matched_free_host = free_host
                break

        if matched_free_host:
            indicators["free_hosting"] = True

            score += 0.30

            reasons.append(
                f"Third-party/free hosting platform detected "
                f"({matched_free_host})"
            )

        # Domain Structure
        parts = hostname.split(".")

        registered_domain = (
            ".".join(parts[-2:])
            if len(parts) >= 2
            else hostname
        )

        domain_label = (
            parts[-2]
            if len(parts) >= 2
            else hostname
        )

        subdomains = (
            parts[:-2]
            if len(parts) > 2
            else []
        )

        suspicious_subdomains = [
            sub
            for sub in subdomains
            if sub not in cls.COMMON_SUBDOMAINS
        ]

        subdomain_depth = len(subdomains)

        # Brand Impersonation
        for brand in cls.get_target_brands():
            if len(brand) < 4:
                continue

            domain_lower = domain_label.lower()

            if domain_lower == brand.lower():
                continue

            dist = levenshtein_distance(
                domain_lower,
                brand.lower(),
            )

            if (
                0 < dist <= 2
                and len(domain_lower) >= 4
            ):
                indicators["brand_impersonation"] = True
                indicators["suspicious_hostname"] = True

                score += 0.40

                reasons.append(
                    f"Potential brand impersonation: "
                    f"'{domain_label}' resembles '{brand}' "
                    f"(distance: {dist})"
                )

                break

        # Suspicious Hostname Tokens
        suspicious_hostname_tokens = []

        for keyword in cls.SUSPICIOUS_KEYWORDS:
            if keyword in domain_label.lower():
                suspicious_hostname_tokens.append(keyword)

        if suspicious_hostname_tokens:
            indicators["suspicious_hostname"] = True

            score += min(
                0.10 * len(suspicious_hostname_tokens),
                0.30,
            )

            reasons.append(
                "Suspicious hostname tokens detected: "
                + ", ".join(suspicious_hostname_tokens)
            )

        # Suspicious Subdomain
        suspicious_subdomain_tokens = []

        for subdomain in suspicious_subdomains:
            for keyword in cls.SUSPICIOUS_KEYWORDS:
                if keyword in subdomain.lower():
                    suspicious_subdomain_tokens.append(
                        f"{subdomain}:{keyword}"
                    )

        if suspicious_subdomain_tokens:
            indicators["suspicious_subdomain"] = True
            indicators["suspicious_hostname"] = True

            score += 0.20

            reasons.append(
                "Suspicious subdomain detected: "
                + ", ".join(suspicious_subdomain_tokens[:5])
            )

        elif len(suspicious_subdomains) >= 2:
            indicators["suspicious_subdomain"] = True

            score += 0.10

            reasons.append(
                f"Deep subdomain structure "
                f"({subdomain_depth} levels)"
            )

        # Entropy
        entropy = cls.calculate_entropy(hostname)

        if entropy > 3.8:
            indicators["high_entropy"] = True
            indicators["suspicious_hostname"] = True

            score += 0.20

            reasons.append(
                f"High domain entropy detected ({entropy})"
            )

        # WHOIS
        try:
            whois_info = check_whois_domain.invoke(
                {
                    "domain": registered_domain
                }
            )

            match = re.search(
                r"Domain age:\s*(\d+)",
                whois_info,
                re.IGNORECASE,
            )

            if match:
                days = int(match.group(1))

                if days < 30:
                    indicators["new_domain"] = True

                    score += 0.40

                    reasons.append(
                        f"Newly registered domain "
                        f"({days} days old)"
                    )

                elif days < 90:
                    indicators["recent_domain"] = True

                    score += 0.20

                    reasons.append(
                        f"Recently registered domain "
                        f"({days} days old)"
                    )

        except Exception:
            pass

        return {
            "domain_confidence": round(
                min(score, 1.0),
                2,
            ),
            "reasons": reasons,
            "indicators": indicators,
            "entropy": entropy,
            "subdomain_depth": subdomain_depth,
            "hostname": hostname,
            "registered_domain": registered_domain,
            "domain_label": domain_label,
            "suspicious_hostname_tokens": suspicious_hostname_tokens,
            "suspicious_subdomains": suspicious_subdomains,
        }

    # URL String Analysis
    @classmethod
    def analyze_string(cls, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)

        hostname = parsed.hostname or ""
        full_url_lower = url.lower()

        score = 0.0
        reasons = []

        indicators = {
            "url_shortener": False,
            "suspicious_tld": False,
            "suspicious_keywords": False,
            "insecure_http": False,
            "long_url": False,
        }

        # URL Shortener
        if hostname in cls.URL_SHORTENERS:
            indicators["url_shortener"] = True

            score += 0.35

            reasons.append(
                "URL shortener service detected"
            )

        # TLD
        tld = (
            hostname.split(".")[-1]
            if "." in hostname
            else ""
        )

        if tld in cls.SUSPICIOUS_TLDS:
            indicators["suspicious_tld"] = True

            score += 0.25

            reasons.append(
                f"Suspicious TLD detected: .{tld}"
            )

        # Suspicious Keywords
        matched_keywords = [
            keyword
            for keyword in cls.SUSPICIOUS_KEYWORDS
            if keyword in full_url_lower
        ]

        if matched_keywords:
            indicators["suspicious_keywords"] = True

            score += min(
                0.10 * len(matched_keywords),
                0.35,
            )

            reasons.append(
                "Suspicious URL keywords detected: "
                + ", ".join(matched_keywords)
            )

        # Protocol
        if parsed.scheme.lower() != "https":
            indicators["insecure_http"] = True

            score += 0.15

            reasons.append(
                "Insecure HTTP protocol detected"
            )

        # URL Length
        if len(url) > 100:
            indicators["long_url"] = True

            score += 0.15

            reasons.append(
                f"Unusually long URL "
                f"({len(url)} characters)"
            )

        return {
            "string_confidence": round(
                min(score, 1.0),
                2,
            ),
            "reasons": reasons,
            "indicators": indicators,
            "matched_keywords": matched_keywords,
        }

    # Page and Transit Analysis
    @classmethod
    def inspect_transit_and_page(
        cls,
        url: str,
    ) -> Dict[str, Any]:

        score = 0.0
        reasons = []

        redirect_chain = []
        external_links = []

        indicators = {
            "cross_domain_redirect": False,
            "meta_refresh": False,
            "password_form": False,
            "credential_form": False,
            "hidden_iframe": False,
            "suspicious_external_link": False,
            "http_error": False,
            "connection_failed": False,
        }

        headers = {
            "User-Agent": cls.USER_AGENT
        }

        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=8,
                allow_redirects=True,
            )

            # HTTP Status
            if response.status_code >= 400:
                indicators["http_error"] = True

                score += 0.10

                reasons.append(
                    f"HTTP error response detected "
                    f"({response.status_code})"
                )

            # Redirect Chain
            if response.history:
                for resp in response.history:
                    redirect_chain.append(resp.url)

                redirect_chain.append(response.url)

                original_domain = (
                    urlparse(url).hostname or ""
                ).lower()

                final_domain = (
                    urlparse(response.url).hostname or ""
                ).lower()

                if (
                    original_domain
                    and final_domain
                    and original_domain != final_domain
                ):
                    indicators["cross_domain_redirect"] = True

                    score += 0.35

                    reasons.append(
                        "Cross-domain redirect detected: "
                        f"{original_domain} -> {final_domain}"
                    )

            # Content Type
            content_type = response.headers.get(
                "Content-Type",
                "",
            ).lower()

            if "text/html" not in content_type:
                return {
                    "transit_confidence": round(
                        min(score, 1.0),
                        2,
                    ),
                    "reasons": reasons,
                    "indicators": indicators,
                    "redirect_chain": redirect_chain,
                    "external_links_count": 0,
                }

            soup = BeautifulSoup(
                response.text,
                "html.parser",
            )

            # Meta Refresh
            meta_refresh = soup.find(
                "meta",
                attrs={
                    "http-equiv": re.compile(
                        r"refresh",
                        re.I,
                    )
                },
            )

            if meta_refresh:
                indicators["meta_refresh"] = True

                score += 0.25

                reasons.append(
                    "Client-side Meta Refresh detected"
                )

            # Password and Credential Forms
            password_inputs = soup.find_all(
                "input",
                {
                    "type": re.compile(
                        r"password",
                        re.I,
                    )
                },
            )

            credential_keywords = {
                "password",
                "username",
                "user",
                "email",
                "login",
                "signin",
                "sign-in",
                "credential",
                "pin",
                "otp",
            }

            credential_inputs = []

            for input_tag in soup.find_all("input"):
                input_type = (
                    input_tag.get("type", "")
                    .lower()
                )

                input_name = (
                    input_tag.get("name", "")
                    .lower()
                )

                input_placeholder = (
                    input_tag.get("placeholder", "")
                    .lower()
                )

                input_id = (
                    input_tag.get("id", "")
                    .lower()
                )

                combined = " ".join(
                    [
                        input_type,
                        input_name,
                        input_placeholder,
                        input_id,
                    ]
                )

                if any(
                    keyword in combined
                    for keyword in credential_keywords
                ):
                    credential_inputs.append(
                        input_tag
                    )

            if password_inputs:
                indicators["password_form"] = True
                indicators["credential_form"] = True

                score += 0.45

                reasons.append(
                    "Password input / credential "
                    "harvesting form detected"
                )

            elif len(credential_inputs) >= 2:
                indicators["credential_form"] = True

                score += 0.30

                reasons.append(
                    "Multiple credential-related "
                    "input fields detected"
                )

            # Hidden Iframe
            for iframe in soup.find_all("iframe"):
                style = iframe.get(
                    "style",
                    "",
                ).lower()

                width = iframe.get(
                    "width",
                    "",
                )

                height = iframe.get(
                    "height",
                    "",
                )

                if (
                    "display:none" in style
                    or "visibility:hidden" in style
                    or width == "0"
                    or height == "0"
                ):
                    indicators["hidden_iframe"] = True

                    score += 0.25

                    reasons.append(
                        "Hidden iframe detected"
                    )

                    break

            # External Links
            base_domain = (
                urlparse(response.url).hostname
                or ""
            ).lower()

            suspicious_external_keywords = {
                "slot",
                "gacor",
                "apk",
                "login",
                "verify",
                "verification",
                "claim",
                "bonus",
                "wallet",
            }

            for a_tag in soup.find_all(
                "a",
                href=True,
            ):
                href = a_tag["href"]

                if href.startswith(
                    (
                        "#",
                        "javascript:",
                        "mailto:",
                        "tel:",
                    )
                ):
                    continue

                full_link = urljoin(
                    response.url,
                    href,
                )

                link_domain = (
                    urlparse(full_link).hostname
                    or ""
                ).lower()

                if (
                    link_domain
                    and link_domain != base_domain
                ):
                    external_links.append(full_link)

                    if any(
                        keyword
                        in full_link.lower()
                        for keyword
                        in suspicious_external_keywords
                    ):
                        indicators[
                            "suspicious_external_link"
                        ] = True

                        score += 0.20

                        reasons.append(
                            "Suspicious external link detected: "
                            f"{link_domain}"
                        )

                        break

        except requests.RequestException as e:
            indicators["connection_failed"] = True

            score += 0.10

            reasons.append(
                f"Website could not be reached "
                f"({type(e).__name__})"
            )

        return {
            "transit_confidence": round(
                min(score, 1.0),
                2,
            ),
            "reasons": reasons,
            "indicators": indicators,
            "redirect_chain": redirect_chain,
            "external_links_count": len(
                external_links
            ),
        }

    # LLM Engine
    @classmethod
    def get_llm_chain(cls):
        if cls._llm_chain is not None:
            return cls._llm_chain

        try:
            tokenizer = AutoTokenizer.from_pretrained(
                cls.LLM_MODEL_NAME
            )

            model = AutoModelForSeq2SeqLM.from_pretrained(
                cls.LLM_MODEL_NAME
            )

            pipe = pipeline(
                "text2text-generation",
                model=model,
                tokenizer=tokenizer,
                max_new_tokens=256,
            )

            llm = HuggingFacePipeline(
                pipeline=pipe
            )

            prompt = ChatPromptTemplate.from_messages(
                [
                    (
                        "system",
                        """
You are a cybersecurity analyst specializing in malicious URL detection.

Analyze the target URL for phishing, scam, impersonation, credential harvesting,
malicious redirects, suspicious hosting, and other security indicators.

Return ONLY valid JSON:

{
    "verdict": "PHISHING" | "SUSPICIOUS" | "SAFE",
    "confidence": 0.0,
    "reasons": ["reason 1", "reason 2"]
}

Confidence must be between 0.0 and 1.0.
""",
                    ),
                    (
                        "user",
                        "Target URL: {url}",
                    ),
                ]
            )

            cls._llm_chain = (
                prompt
                | llm
                | JsonOutputParser()
            )

        except Exception:
            cls._llm_chain = False

        return cls._llm_chain

    # LLM Analysis
    @classmethod
    def analyze_with_llm(
        cls,
        url: str,
    ) -> Dict[str, Any]:

        try:
            chain = cls.get_llm_chain()

            if not chain:
                raise RuntimeError(
                    "LLM pipeline unavailable"
                )

            result = chain.invoke(
                {
                    "url": url
                }
            )

            verdict = str(
                result.get(
                    "verdict",
                    "UNKNOWN",
                )
            ).upper()

            confidence = float(
                result.get(
                    "confidence",
                    0.0,
                )
            )

            confidence = max(
                0.0,
                min(confidence, 1.0),
            )

            if verdict == "PHISHING":
                threat_score = confidence

            elif verdict == "SUSPICIOUS":
                threat_score = confidence * 0.60

            elif verdict == "SAFE":
                threat_score = 0.0

            else:
                threat_score = 0.0

            return {
                "llm_confidence": round(
                    confidence,
                    2,
                ),
                "llm_reasons": result.get(
                    "reasons",
                    [],
                ),
                "llm_prediction": verdict,
                "llm_score": round(
                    threat_score,
                    2,
                ),
            }

        except Exception as e:
            return {
                "llm_confidence": 0.0,
                "llm_reasons": [
                    f"LLM unavailable: {str(e)}"
                ],
                "llm_prediction": "UNKNOWN",
                "llm_score": 0.0,
            }

    # Score Aggregation
    @classmethod
    def calculate_final_score(
        cls,
        domain_res: Dict[str, Any],
        transit_res: Dict[str, Any],
        string_res: Dict[str, Any],
        llm_res: Dict[str, Any],
        vt_res: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        # Check if domain is whitelisted
        if domain_res.get("is_whitelisted", False):
            return {
                "final_score": 0.0,
                "weighted_score": 0.0,
                "critical_reasons": ["Domain is whitelisted as safe"],
            }

        domain_score = domain_res[
            "domain_confidence"
        ]

        transit_score = transit_res[
            "transit_confidence"
        ]

        string_score = string_res[
            "string_confidence"
        ]

        llm_score = llm_res[
            "llm_score"
        ]

        domain_flags = domain_res.get(
            "indicators",
            {},
        )

        transit_flags = transit_res.get(
            "indicators",
            {},
        )

        string_flags = string_res.get(
            "indicators",
            {},
        )

        # Weighted Base Score
        weighted_score = (
            domain_score * cls.DOMAIN_WEIGHT
            + transit_score * cls.TRANSIT_WEIGHT
            + string_score * cls.STRING_WEIGHT
            + llm_score * cls.LLM_WEIGHT
        )

        critical_reasons = []
        critical_score = weighted_score

        # Critical Rule: Free Hosting + Password
        if (
            domain_flags.get("free_hosting")
            and transit_flags.get("password_form")
        ):
            critical_score = max(
                critical_score,
                0.85,
            )

            critical_reasons.append(
                "Credential harvesting form detected "
                "on third-party/free-hosting infrastructure"
            )

        # Critical Rule: New Domain + Password
        if (
            domain_flags.get("new_domain")
            and transit_flags.get("password_form")
        ):
            critical_score = max(
                critical_score,
                0.90,
            )

            critical_reasons.append(
                "Newly registered domain combined "
                "with credential harvesting form"
            )

        # Critical Rule: Brand Impersonation + Password
        if (
            domain_flags.get("brand_impersonation")
            and transit_flags.get("password_form")
        ):
            critical_score = max(
                critical_score,
                0.95,
            )

            critical_reasons.append(
                "Potential brand impersonation combined "
                "with credential harvesting form"
            )

        # Critical Rule: Suspicious Hostname + Password
        if (
            domain_flags.get("suspicious_hostname")
            and transit_flags.get("password_form")
        ):
            critical_score = max(
                critical_score,
                0.90,
            )

            critical_reasons.append(
                "Suspicious hostname combined "
                "with credential harvesting form"
            )

        # Critical Rule: Suspicious URL + Password
        if (
            string_flags.get("suspicious_keywords")
            and transit_flags.get("password_form")
        ):
            critical_score = max(
                critical_score,
                0.90,
            )

            critical_reasons.append(
                "Suspicious URL keywords combined "
                "with credential harvesting form"
            )

        # Critical Rule: Free Hosting + Suspicious URL + Password
        if (
            domain_flags.get("free_hosting")
            and string_flags.get("suspicious_keywords")
            and transit_flags.get("password_form")
        ):
            critical_score = max(
                critical_score,
                0.95,
            )

            critical_reasons.append(
                "Third-party hosting, suspicious URL keywords, "
                "and credential harvesting form detected together"
            )

        # Critical Rule: Redirect + Password
        if (
            transit_flags.get("cross_domain_redirect")
            and transit_flags.get("password_form")
        ):
            critical_score = max(
                critical_score,
                0.90,
            )

            critical_reasons.append(
                "Cross-domain redirect combined "
                "with credential harvesting form"
            )

        # Critical Rule: Raw IP + Password
        if (
            domain_flags.get("raw_ip")
            and transit_flags.get("password_form")
        ):
            critical_score = max(
                critical_score,
                0.95,
            )

            critical_reasons.append(
                "Raw IP address combined "
                "with credential harvesting form"
            )

        # Multiple Critical Evidence
        if len(critical_reasons) >= 2:
            critical_score = max(
                critical_score,
                0.95,
            )

        elif len(critical_reasons) == 1:
            critical_score = max(
                critical_score,
                0.85,
            )

        final_score = round(
            min(
                critical_score,
                1.0,
            ),
            2,
        )

        return {
            "final_score": final_score,
            "weighted_score": round(
                weighted_score,
                2,
            ),
            "critical_reasons": critical_reasons,
        }

    # Classification
    @classmethod
    def classify_score(
        cls,
        score: float,
        is_whitelisted: bool = False,
    ) -> Dict[str, str]:
        score_percent = score * 100

        # Whitelisted domains selalu AMAN
        if is_whitelisted:
            return {
                "verdict": ScanLog.Classification.SAFE,
                "threat_level": "LOW",
                "message": "AMAN (100.0%) - Domain ini adalah domain resmi yang terdaftar dalam whitelist.",
                "advice": "Domain ini aman dan merupakan situs resmi. Tetap waspada saat memasukkan data pribadi."
            }

        if score >= cls.SAFE_THRESHOLD:
            return {
                "verdict": ScanLog.Classification.SAFE,
                "threat_level": "LOW",
                "message": f"AMAN ({score_percent:.1f}%) - URL ini aman untuk dikunjungi.",
                "advice": "Tetap waspada dan periksa URL sebelum memasukkan data pribadi."
            }

        if score >= cls.SUSPICIOUS_THRESHOLD:
            return {
                "verdict": ScanLog.Classification.SUSPICIOUS,
                "threat_level": "HIGH",
                "message": f"MENCURIGAKAN ({score_percent:.1f}%) - URL ini mencurigakan.",
                "advice": "HATI-HATI: JANGAN berikan nomor WA, Telegram, NIK, KTP, atau data pribadi lainnya. Verifikasi terlebih dahulu ke pihak resmi."
            }

        return {
            "verdict": ScanLog.Classification.PHISHING,
            "threat_level": "CRITICAL",
            "message": f"BERBAHAYA/PHISHING ({score_percent:.1f}%) - URL ini terdeteksi sebagai phishing!",
            "advice": "WARNING: JANGAN DIBUKA! URL ini berbahaya. Dapat mencuri data pribadi, kredensial, atau menginstall malware."
        }

    # Main Scan Pipeline
    @classmethod
    def scan_and_save(
        cls,
        url: str,
    ) -> ScanLog:

        url = cls.normalize_url(url)
        domain_res = cls.analyze_domain(url)

        # Early return jika domain whitelisted
        if domain_res.get("is_whitelisted", False):
            final_score = 0.0
            classification = cls.classify_score(final_score, is_whitelisted=True)
            verdict = classification["verdict"]
            threat_level = classification["threat_level"]
            classification_message = classification.get("message", "")
            classification_advice = classification.get("advice", "")
            notes = classification_message

            hermes_result = {
                "verdict": verdict,
                "confidence_score": final_score,
                "risk_score": final_score,
                "ai_notes": notes,
                "threat_level": threat_level,
                "message": classification_message,
                "advice": classification_advice,
                "score_breakdown": {"domain": 0.0, "transit": 0.0, "string": 0.0, "llm": 0.0},
                "weights": {"domain": 0.0, "transit": 0.0, "string": 0.0, "llm": 0.0},
                "weighted_score": 0.0,
                "critical_reasons": ["Domain is whitelisted as safe"],
                "evidence": {"domain": {}, "transit": {}, "string": {}},
            }

            return ScanLog.objects.create(
                url=url,
                classification=verdict,
                confidence_score=final_score,
                string_analysis_detail={"domain": domain_res, "string": {}, "transit": {}},
                hermes_verification_detail=hermes_result,
                llm_analysis_detail={},
            )
        string_res = cls.analyze_string(url)
        transit_res = cls.inspect_transit_and_page(url)
        llm_res = cls.analyze_with_llm(url)

        score_result = cls.calculate_final_score(
            domain_res=domain_res,
            transit_res=transit_res,
            string_res=string_res,
            llm_res=llm_res,
            vt_res=None,
        )

        final_score = score_result[
            "final_score"
        ]

        weighted_score = score_result[
            "weighted_score"
        ]

        critical_reasons = score_result[
            "critical_reasons"
        ]

        classification = cls.classify_score(
            final_score
        )

        verdict = classification[
            "verdict"
        ]

        threat_level = classification[
            "threat_level"
        ]

        classification_message = classification.get("message", "")
        classification_advice = classification.get("advice", "")

        all_reasons = (
            domain_res["reasons"]
            + string_res["reasons"]
            + transit_res["reasons"]
        )

        display_reasons = (
            critical_reasons
            + all_reasons
        )

        notes = classification_message
        if display_reasons:
            notes += " | " + " | ".join(display_reasons[:3])

        hermes_result = {
            "verdict": verdict,
            "confidence_score": final_score,
            "risk_score": final_score,
            "ai_notes": notes,
            "threat_level": threat_level,
            "message": classification_message,
            "advice": classification_advice,

            "score_breakdown": {
                "domain": domain_res[
                    "domain_confidence"
                ],
                "transit": transit_res[
                    "transit_confidence"
                ],
                "string": string_res[
                    "string_confidence"
                ],
                "llm": llm_res[
                    "llm_score"
                ],
            },

            "weights": {
                "domain": cls.DOMAIN_WEIGHT,
                "transit": cls.TRANSIT_WEIGHT,
                "string": cls.STRING_WEIGHT,
                "llm": cls.LLM_WEIGHT,
            },

            "weighted_score": weighted_score,

            "critical_rules": critical_reasons,

            "evidence": {
                "domain": domain_res.get(
                    "indicators",
                    {},
                ),
                "transit": transit_res.get(
                    "indicators",
                    {},
                ),
                "string": string_res.get(
                    "indicators",
                    {},
                ),
            },
        }

        return ScanLog.objects.create(
            url=url,
            classification=verdict,
            confidence_score=final_score,

            string_analysis_detail={
                "domain": domain_res,
                "string": string_res,
                "transit": transit_res,
            },

            hermes_verification_detail=hermes_result,

            llm_analysis_detail=llm_res,
        )