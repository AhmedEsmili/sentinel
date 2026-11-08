package dev.sentinel.scam

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScamAnalyzerTest {
    @Test fun lookalikeBrandWithUrgencyIsLikelyScam() {
        val r = ScamAnalyzer.analyze("URGENT: your PayPal account will be suspended. Verify now: http://paypal-secure-login.top/verify")
        assertEquals(Level.LIKELY_SCAM, r.level)
        assertTrue(r.findings.any { it.title == "Imitates paypal" })
    }

    @Test fun officialDomainIsNotFlaggedAsImitation() {
        val r = ScamAnalyzer.analyze("Your receipt: https://www.paypal.com/myaccount")
        assertTrue(r.findings.none { it.title.startsWith("Imitates") })
    }

    @Test fun giftCardAndSecrecyIsFlagged() {
        val r = ScamAnalyzer.analyze("Buy gift cards and don't tell anyone, send me the codes")
        assertEquals(Level.LIKELY_SCAM, r.level)
    }

    @Test fun ordinaryMessageHasNoFlags() {
        assertEquals(Level.NO_FLAGS, ScamAnalyzer.analyze("Lunch at 1? I'll grab a table.").level)
    }

    @Test fun registeredDomainHandlesCoUk() {
        assertEquals("amazon.co.uk", ScamAnalyzer.registeredDomain("www.amazon.co.uk"))
    }
}
