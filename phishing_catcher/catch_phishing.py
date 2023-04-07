#!/usr/bin/env python
# Copyright (c) 2017 @x0rz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import re
import math
import logging
from typing import List
from pathlib import Path

import certstream
import yaml
import time
import os
from Levenshtein import distance
from termcolor import colored
from tld import get_tld
from loguru import logger

from confusables import unconfuse

certstream_url = "wss://certstream.calidog.io"

log_suspicious = Path(
    os.path.dirname(os.path.realpath(__file__))) / "../logs" / f"suspicious_domains_{time.strftime('%Y-%m-%d')}.log"

suspicious_yaml = Path(os.path.dirname(os.path.realpath(__file__))) / "../suspicious.yaml"

external_yaml = Path(os.path.dirname(os.path.realpath(__file__))) / "../external.yaml"


def entropy(string):
    """Calculates the Shannon entropy of a string"""
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


def score_domain(domain):
    """Score `domain`.

    The highest score, the most probable `domain` is a phishing site.

    Args:
        domain (str): the domain to check.

    Returns:
        int: the score of `domain`.
    """
    score = 0
    for t in suspicious["tlds"]:
        if domain.endswith(t):
            score += 20

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith("*."):
        domain = domain[2:]

    # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        domain = ".".join([res.subdomain, res.domain])
    except Exception:
        pass

    # Higer entropy is kind of suspicious
    score += int(round(entropy(domain) * 10))

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)

    words_in_domain = re.split("\W+", domain)

    # ie. detect fake .com (ie. *.com-account-management.info)
    if words_in_domain[0] in ["com", "net", "org"]:
        score += 10

    # Testing keywords
    for word in suspicious["keywords"]:
        if word in domain:
            score += suspicious["keywords"][word]

    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    for key in [k for (k, s) in suspicious["keywords"].items() if s >= 70]:
        # Removing too generic keywords (ie. mail.domain.com)
        for word in [w for w in words_in_domain if w not in ["email", "mail", "cloud"]]:
            if distance(str(word), str(key)) == 1:
                score += 70

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if "xn--" not in domain and domain.count("-") >= 4:
        score += domain.count("-") * 3

    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    if domain.count(".") >= 3:
        score += domain.count(".") * 3

    return score


def callback(message, context):
    """Callback handler for certstream events."""
    if message["message_type"] == "heartbeat":
        return

    if message["message_type"] == "certificate_update":
        all_domains: List[str] = message["data"]["leaf_cert"]["all_domains"]

        for domain in all_domains:
            domain = domain.lower()
            if not domain.endswith(".cc") and len(domain) > suspicious["domain_max_length"]:
                continue

            score = score_domain(domain.lower())

            # If issued from a free CA = more suspicious
            if "Let's Encrypt" == message["data"]["leaf_cert"]["issuer"]["O"]:
                score += 10

            if score >= 100:
                logger.info(
                    "[!] Suspicious: "
                    "{} (score={})".format(
                        colored(domain, "red", attrs=["underline", "bold"]), score
                    )
                )
            elif score >= 90:
                logger.info(
                    "[!] Suspicious: "
                    "{} (score={})".format(
                        colored(domain, "red", attrs=["underline"]), score
                    )
                )
            elif score >= 80:
                logger.info(
                    "[!] Likely    : "
                    "{} (score={})".format(
                        colored(domain, "yellow", attrs=["underline"]), score
                    )
                )
            elif score >= 65:
                logger.info(
                    "[+] Potential : "
                    "{} (score={})".format(
                        colored(domain, "green", attrs=["underline"]), score
                    )
                )

            if score >= 75:
                with open(log_suspicious, "a") as f:
                    f.write("{}\n".format(domain))


class InterceptHandler(logging.Handler):
    def emit(self, record):
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find caller from where originated the logged message
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


if __name__ == "__main__":
    logging.basicConfig(handlers=[InterceptHandler()], level=logging.INFO)

    if not os.path.exists("logs"):
        os.makedirs("logs")

    with open(suspicious_yaml, "r") as f:
        suspicious = yaml.safe_load(f)

    with open(external_yaml, "r") as f:
        external = yaml.safe_load(f)

    if external["override_suspicious.yaml"] is True:
        suspicious = external
    else:
        if external["keywords"] is not None:
            suspicious["keywords"].update(external["keywords"])

        if external["tlds"] is not None:
            suspicious["tlds"].update(external["tlds"])

    certstream.listen_for_events(callback, url=certstream_url)
