# Phishing URL Awareness Checker – Test Cases

## Test Case 1: Normal HTTPS URL

**Input:**

```text
https://www.example.com/login
```

**Expected Result:**

```text
No listed warning signs found. This does NOT prove safety.
```

**Status:** Pass / Fail

---

## Test Case 2: IP Address URL

**Input:**

```text
http://192.0.2.10/account
```

**Expected Warning Signs:**

* Uses an IP address instead of a familiar domain.
* Uses HTTP. HTTPS alone does not prove trust.

**Status:** Pass / Fail

---

## Test Case 3: URL Contains @ Symbol

**Input:**

```text
http://example.com@sample.invalid/login
```

**Expected Warning Signs:**

* Contains an @ symbol; inspect carefully.
* Uses HTTP. HTTPS alone does not prove trust.

**Status:** Pass / Fail

---

## Test Case 4: Many Subdomains

**Input:**

```text
https://a.b.c.d.e.example.invalid/path
```

**Expected Warning Sign:**

* Contains many hostname segments/subdomains.

**Status:** Pass / Fail

---

## Test Case 5: Punycode URL

**Input:**

```text
https://xn--example.invalid/
```

**Expected Warning Sign:**

* Contains a punycode-style hostname.

**Status:** Pass / Fail

---

## Conclusion

The program checks URLs for selected warning signs.
It does not open URLs or guarantee website safety.
