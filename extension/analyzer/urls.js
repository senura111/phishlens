// URLs, hosts, IP addresses and registrable domains, exactly as the Python reference
// reads them (model/src/features.py: host_of, is_ip, registrable_domain).
//
// The browser's own URL parser (new URL()) can't be used: it follows a different
// standard than Python's urllib. For example it turns "http://3232235777/" into
// 192.168.1.1 and international names into xn-- form, so the rules would see a
// different host than Python does. These functions copy urllib.parse.urlsplit,
// ipaddress.ip_address and publicsuffixlist step by step instead.

import { MAX_LABELS, PUBLIC_SUFFIXES } from "./generated/public-suffixes.js";
import { isAscii, isDigit, pyStrip } from "./python-compat.js";

// --- urllib.parse.urlsplit ----------------------------------------------------------

// Thrown where Python's urlsplit raises ValueError.
export class UrlError extends Error {}

const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*$/;

// Splits a URL into { scheme, netloc, path, query, fragment } like urlsplit().
// Throws UrlError where urlsplit raises ValueError (e.g. "http://[oops").
export function urlsplit(url) {
  // Leading control characters and spaces are dropped, and tabs and line breaks
  // removed everywhere.
  url = url.replace(/^[\x00-\x20]+/, "").replace(/[\t\r\n]/g, "");
  let scheme = "";
  let netloc = "";
  let query = "";
  let fragment = "";
  const colon = url.indexOf(":");
  if (colon > 0 && SCHEME.test(url.slice(0, colon))) {
    scheme = url.slice(0, colon).toLowerCase();
    url = url.slice(colon + 1);
  }
  if (url.startsWith("//")) {
    let end = url.length;
    for (const delimiter of "/?#") {
      const at = url.indexOf(delimiter, 2);
      if (at >= 0) {
        end = Math.min(end, at);
      }
    }
    netloc = url.slice(2, end);
    url = url.slice(end);
    if (netloc.includes("[") !== netloc.includes("]")) {
      throw new UrlError("Invalid IPv6 URL");
    }
    if (netloc.includes("[")) {
      checkBracketedNetloc(netloc);
    }
  }
  const hash = url.indexOf("#");
  if (hash >= 0) {
    fragment = url.slice(hash + 1);
    url = url.slice(0, hash);
  }
  const question = url.indexOf("?");
  if (question >= 0) {
    query = url.slice(question + 1);
    url = url.slice(0, question);
  }
  checkNetloc(netloc);
  return { scheme, netloc, path: url, query, fragment };
}

// "[...]" must be the whole host, optionally followed by ":port".
function checkBracketedNetloc(netloc) {
  const hostAndPort = netloc.slice(netloc.lastIndexOf("@") + 1);
  const open = hostAndPort.indexOf("[");
  if (open < 0) {
    return;
  }
  if (open > 0) {
    throw new UrlError("Invalid IPv6 URL");
  }
  const bracketed = hostAndPort.slice(open + 1);
  const close = bracketed.indexOf("]");
  const hostname = close >= 0 ? bracketed.slice(0, close) : bracketed;
  const port = close >= 0 ? bracketed.slice(close + 1) : "";
  if (port && !port.startsWith(":")) {
    throw new UrlError("Invalid IPv6 URL");
  }
  // An IPv6 address, or the rare "IPvFuture" form (v1.something).
  if (hostname.startsWith("v") || hostname.startsWith("V")) {
    if (!/^[vV][a-fA-F0-9]+\.[^\n]+$/.test(hostname)) {
      throw new UrlError("IPvFuture address is invalid");
    }
  } else if (isIPv4(hostname) || !isIPv6(hostname)) {
    throw new UrlError("Not an IPv6 address");
  }
}

// Characters such as U+2100 (the "a/c" symbol) turn into "/" and friends under NFKC
// normalisation, which could move where the host ends. Python refuses such hosts.
function checkNetloc(netloc) {
  if (!netloc || isAscii(netloc)) {
    return;
  }
  const n = netloc.replace(/[@:#?]/g, "");
  const normalized = n.normalize("NFKC");
  if (n !== normalized && /[/?#@:]/.test(normalized)) {
    throw new UrlError("netloc contains invalid characters under NFKC normalization");
  }
}

// The .hostname of a urlsplit() result: lowercase, without user, password or port.
// null when there is none.
function hostnameOf(netloc) {
  const hostInfo = netloc.slice(netloc.lastIndexOf("@") + 1);
  const open = hostInfo.indexOf("[");
  let hostname;
  if (open >= 0) {
    const bracketed = hostInfo.slice(open + 1);
    const close = bracketed.indexOf("]");
    hostname = close >= 0 ? bracketed.slice(0, close) : bracketed;
  } else {
    const colon = hostInfo.indexOf(":");
    hostname = colon >= 0 ? hostInfo.slice(0, colon) : hostInfo;
  }
  if (!hostname) {
    return null;
  }
  // An IPv6 zone ("fe80::1%eth0") keeps its case.
  const percent = hostname.indexOf("%");
  if (percent < 0) {
    return hostname.toLowerCase();
  }
  return hostname.slice(0, percent).toLowerCase() + hostname.slice(percent);
}

// features.host_of(): the lowercase host of a URL, or "" if it can't be parsed.
export function hostOf(url) {
  url = pyStrip(url);
  if (!url.includes("://")) {
    url = "http://" + url;
  }
  let host;
  try {
    host = hostnameOf(urlsplit(url).netloc) ?? "";
  } catch (error) {
    if (error instanceof UrlError) {
      return "";
    }
    throw error;
  }
  return host.replace(/\.+$/, "").toLowerCase();
}

// --- ipaddress.ip_address -----------------------------------------------------------

// features.is_ip(): 185.22.10.4, ::1, and all-digit hosts (browsers read 3232235777
// as an IP address).
export function isIp(host) {
  return isDigit(host) || isIPv4(host) || isIPv6(host);
}

// ipaddress.IPv4Address: four decimal numbers 0-255, no leading zeros.
function isIPv4(text) {
  if (text.includes("/")) {
    return false;
  }
  const octets = text.split(".");
  return (
    octets.length === 4 &&
    octets.every(
      (octet) =>
        /^[0-9]{1,3}$/.test(octet) &&
        (octet === "0" || octet[0] !== "0") &&
        Number(octet) <= 255
    )
  );
}

const HEXTET = /^[0-9a-fA-F]{1,4}$/;
const HEXTET_COUNT = 8;

// ipaddress.IPv6Address, including "::" shortening, an IPv4 ending (::ffff:1.2.3.4)
// and a zone after "%".
function isIPv6(text) {
  if (text.includes("/")) {
    return false;
  }
  const percent = text.indexOf("%");
  if (percent >= 0) {
    const zone = text.slice(percent + 1);
    if (!zone || zone.includes("%")) {
      return false;
    }
    text = text.slice(0, percent);
  }
  if (!text || text.length > 45) {
    return false;
  }
  let parts = text.split(":");
  if (parts.length < 3) {
    return false;
  }
  if (parts[parts.length - 1].includes(".")) {
    if (!isIPv4(parts.pop())) {
      return false;
    }
    parts.push("0", "0"); // the IPv4 part counts as two hextets
  }
  if (parts.length > HEXTET_COUNT + 1) {
    return false;
  }
  // At most one "::" (an empty part that isn't at either end).
  let skipIndex = null;
  for (let i = 1; i < parts.length - 1; i++) {
    if (!parts[i]) {
      if (skipIndex !== null) {
        return false;
      }
      skipIndex = i;
    }
  }
  let high;
  let low;
  if (skipIndex !== null) {
    high = skipIndex;
    low = parts.length - skipIndex - 1;
    if (!parts[0]) {
      high -= 1;
      if (high) {
        return false; // a leading ":" must be part of "::"
      }
    }
    if (!parts[parts.length - 1]) {
      low -= 1;
      if (low) {
        return false; // a trailing ":" must be part of "::"
      }
    }
    if (HEXTET_COUNT - (high + low) < 1) {
      return false;
    }
  } else {
    if (parts.length !== HEXTET_COUNT || !parts[0] || !parts[parts.length - 1]) {
      return false;
    }
    high = parts.length;
    low = 0;
  }
  parts = [...parts.slice(0, high), ...parts.slice(parts.length - low)];
  return parts.every((part) => HEXTET.test(part));
}

// --- publicsuffixlist ---------------------------------------------------------------

// PublicSuffixList.privatesuffix(): the registrable part of a domain
// (login.paypal.com -> paypal.com), or null when the domain is itself a public
// suffix ("co.uk") or isn't a valid name ("a..com").
function privateSuffix(domain) {
  if (domain.endsWith(".")) {
    domain = domain.slice(0, -1);
  }
  const labels = domain.toLowerCase().split(".");
  if (labels.includes("")) {
    return null;
  }
  const publicLength = countPublic(labels);
  if (labels.length < publicLength + 1) {
    return null;
  }
  return labels.slice(labels.length - publicLength - 1).join(".");
}

// How many labels at the end of the domain form its public suffix. Unknown top-level
// domains count as public suffixes. Wildcard rules (*.ck) and exceptions (!www.ck)
// follow the publicsuffixlist package's rules, checked longest first.
function countPublic(labels) {
  const count = labels.length;
  if (count === 1) {
    return 1;
  }
  for (let i = Math.max(0, count - (MAX_LABELS + 1)); i < count; i++) {
    const depth = count - i;
    const suffix = labels.slice(i).join(".");
    if (PUBLIC_SUFFIXES.has("!" + suffix)) {
      return depth - 1;
    }
    if (PUBLIC_SUFFIXES.has("*." + suffix)) {
      return i > 0 ? depth + 1 : depth;
    }
    if (PUBLIC_SUFFIXES.has(suffix)) {
      return depth;
    }
  }
  return 1;
}

// features.registrable_domain(): the part of a host you have to buy.
// login.paypal.com -> paypal.com, www.ecu.edu.lk -> ecu.edu.lk. IPs stay as they are.
export function registrableDomain(host) {
  if (isIp(host)) {
    return host;
  }
  return privateSuffix(host) || host;
}

// --- urllib.parse.unquote -----------------------------------------------------------

// ignoreBOM: true keeps a leading U+FEFF in the output, like Python's UTF-8 decoder.
// Invalid UTF-8 becomes U+FFFD, like Python's errors="replace".
const utf8 = new TextDecoder("utf-8", { ignoreBOM: true });

// Decodes %xx escapes as UTF-8, like urllib.parse.unquote(). Only runs of ASCII
// characters are decoded; other characters stay as they are.
export function unquote(text) {
  if (!text.includes("%")) {
    return text;
  }
  return text.replace(/[\x00-\x7f]+/g, unquoteAscii);
}

function unquoteAscii(run) {
  const bits = run.split("%");
  const bytes = [];
  const pushText = (part) => {
    for (let i = 0; i < part.length; i++) {
      bytes.push(part.charCodeAt(i));
    }
  };
  pushText(bits[0]);
  for (const item of bits.slice(1)) {
    if (/^[0-9A-Fa-f]{2}/.test(item)) {
      bytes.push(parseInt(item.slice(0, 2), 16));
      pushText(item.slice(2));
    } else {
      bytes.push(0x25); // "%": not an escape, kept as it is
      pushText(item);
    }
  }
  return utf8.decode(new Uint8Array(bytes));
}
