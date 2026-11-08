package dev.sentinel.scam

enum class Level { LIKELY_SCAM, SUSPICIOUS, NO_FLAGS }

data class Finding(val title: String, val why: String, val points: Int)

data class ScamResult(val score: Int, val level: Level, val findings: List<Finding>)

/**
 * Pure-Kotlin, fully on-device scam heuristics (no network, no Android deps => unit-testable).
 * It can only find RED FLAGS. "No flags" never means "safe".
 */
object ScamAnalyzer {

    private val urlRegex = Regex(
        """(?i)\b(?:https?://|www\.)[^\s<>"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|co|info|biz|top|xyz|click|zip|mov|icu|tk|gq|cf|ml|ga|link|live|shop|online|site)\b(?:/[^\s<>"']*)?"""
    )
    private val shorteners = setOf("bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "ow.ly", "shorturl.at", "tiny.cc", "buff.ly")
    private val riskyTlds = setOf("zip", "mov", "top", "xyz", "click", "icu", "tk", "gq", "cf", "ml", "ga", "rest", "cfd", "sbs")
    private val twoPartSuffix = setOf("co.uk", "org.uk", "com.au", "co.in", "com.br", "co.jp", "co.za")
    private val ipHost = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
    private val invisible = Regex("[\\u200B-\\u200F\\u2060\\uFEFF]")

    private val brands: Map<String, Set<String>> = mapOf(
        "paypal" to setOf("paypal.com"),
        "amazon" to setOf("amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com"),
        "apple" to setOf("apple.com", "icloud.com"),
        "microsoft" to setOf("microsoft.com", "live.com", "office.com"),
        "google" to setOf("google.com", "goo.gl", "youtube.com"),
        "netflix" to setOf("netflix.com"),
        "dhl" to setOf("dhl.com", "dhl.de"),
        "fedex" to setOf("fedex.com"),
        "usps" to setOf("usps.com"),
        "chase" to setOf("chase.com"),
        "wellsfargo" to setOf("wellsfargo.com"),
        "bankofamerica" to setOf("bankofamerica.com"),
        "coinbase" to setOf("coinbase.com"),
        "binance" to setOf("binance.com"),
        "whatsapp" to setOf("whatsapp.com", "wa.me"),
        "facebook" to setOf("facebook.com", "fb.com"),
        "instagram" to setOf("instagram.com"),
    )

    private class Rule(val title: String, val why: String, val points: Int, val regex: Regex)

    private fun r(p: String) = Regex(p, RegexOption.IGNORE_CASE)

    private val textRules = listOf(
        Rule("Urgency / pressure", "Scammers rush you so you don't think or verify.", 2,
            r("""\b(urgent(ly)?|immediately|act now|final notice|last warning|within \d+ ?(hours?|hrs?|minutes?)|account (will be )?(suspended|locked|closed)|expires? (today|soon))\b""")),
        Rule("Asks for payment in hard-to-reverse ways", "Gift cards, crypto and wire transfers are scammers' favourites because they can't be clawed back.", 3,
            r("""\b(gift ?cards?|itunes card|wire transfer|western union|moneygram|bitcoin|crypto(currency)?|usdt|zelle|cash ?app)\b""")),
        Rule("Asks for codes or credentials", "Real companies never ask you to share passwords, PINs or one-time codes.", 3,
            r("""\b(password|one[- ]time (code|passcode)|otp|verification code|your pin|ssn|social security|card number|cvv|seed phrase|recovery phrase)\b""")),
        Rule("Prize / windfall bait", "Unexpected winnings are a classic lure to harvest data or fees.", 2,
            r("""\b(you('ve)? won|winner|claim your (prize|reward)|congratulations|lottery|inheritance)\b""")),
        Rule("Fake delivery / toll / fee notice", "Small 'unpaid fee' notices with a link are a very common smishing pattern.", 2,
            r("""\b(unpaid (toll|fee|fine)|customs fee|redelivery|delivery (failed|attempt)|package (is )?(on hold|held)|parcel)\b""")),
        Rule("Impersonates an authority", "Banks, tax agencies and police don't demand action by text.", 1,
            r("""\b(irs|tax refund|police|arrest warrant|your bank|bank security|fraud department|customs and border)\b""")),
        Rule("Asks for secrecy", "'Don't tell anyone' is used to isolate victims from people who'd spot the scam.", 3,
            r("""\b(don'?t tell anyone|keep this (secret|between us)|do not (tell|inform) (anyone|your))\b""")),
        Rule("Family-impersonation opener", "'Hi mum, this is my new number' is a known scam script.", 3,
            r("""\b(hi|hello) (mum|mom|dad)\b.{0,40}\b(new (phone|number)|lost my phone|broke my phone)\b""")),
        Rule("Remote-access / 'tech support' request", "Installing remote-control apps hands scammers your whole phone.", 3,
            r("""\b(anydesk|teamviewer|quicksupport|remote (access|support)|install (this|the) app)\b""")),
    )

    fun analyze(input: String): ScamResult {
        val text = input.trim()
        if (text.isEmpty()) return ScamResult(0, Level.NO_FLAGS, emptyList())
        val found = LinkedHashMap<String, Finding>()
        fun add(f: Finding) { found.putIfAbsent(f.title, f) }

        val urls = urlRegex.findAll(text).map { it.value.trimEnd('.', ',', ')', '!', '?') }.toList()
        for (url in urls) analyzeUrl(url, ::add)

        val hasLink = urls.isNotEmpty()
        for (rule in textRules) {
            if (rule.regex.containsMatchIn(text)) {
                // fee/delivery wording alone is normal; it's only a red flag together with a link
                if (rule.title.startsWith("Fake delivery") && !hasLink) continue
                add(Finding(rule.title, rule.why, rule.points))
            }
        }
        if (invisible.containsMatchIn(text)) {
            add(Finding("Hidden characters", "Invisible characters are used to dodge spam filters.", 2))
        }

        val points = found.values.sumOf { it.points }
        val level = when {
            points >= 6 -> Level.LIKELY_SCAM
            points >= 3 -> Level.SUSPICIOUS
            else -> Level.NO_FLAGS
        }
        return ScamResult(minOf(100, points * 10), level, found.values.sortedByDescending { it.points })
    }

    private fun analyzeUrl(url: String, add: (Finding) -> Unit) {
        val authority = url.replace(Regex("(?i)^https?://"), "").takeWhile { it != '/' && it != '?' && it != '#' }
        val host = authority.substringAfterLast('@').substringBefore(':').trimEnd('.').lowercase()
        if (host.isEmpty()) return

        if ('@' in authority) add(Finding("Link hides its real destination", "Everything before '@' in a URL is ignored; the real site is after it.", 3))
        if (host in shorteners) add(Finding("Shortened link", "You can't see where it goes before tapping.", 2))
        if (ipHost.matches(host)) add(Finding("Link points to a raw IP address", "Legitimate services use domain names.", 3))
        if (host.contains("xn--") || host.any { it.code > 127 }) add(Finding("Look-alike (homograph) domain", "Foreign characters can imitate a trusted brand's letters.", 3))
        if (host.substringAfterLast('.') in riskyTlds) add(Finding("Domain ending often abused", "Cheap or novelty endings are over-represented in phishing.", 2))
        if (host.count { it == '-' } >= 3 || host.count { it == '.' } >= 4) add(Finding("Over-complicated domain", "Long hyphenated or deeply nested names are used to bury the real domain.", 1))

        val registered = registeredDomain(host)
        for ((brand, legit) in brands) {
            if (brand in host && registered !in legit) {
                add(Finding("Imitates $brand", "The link mentions '$brand' but belongs to '$registered', which isn't an official domain.", 4))
                break
            }
        }
    }

    internal fun registeredDomain(host: String): String {
        val labels = host.split('.')
        if (labels.size <= 2) return host
        val last2 = labels.takeLast(2).joinToString(".")
        return if (last2 in twoPartSuffix) labels.takeLast(3).joinToString(".") else last2
    }
}
