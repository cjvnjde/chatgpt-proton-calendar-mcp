package calendar

import (
	"context"
	"strings"
	"testing"
	"time"
)

func openedText(t *testing.T, body string, loc *time.Location) opened {
	t.Helper()
	c, err := parseCard("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n" + body + "\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	if err != nil {
		t.Fatal(err)
	}
	e, err := view(c, body[:3], "cal", "rev", true, loc)
	if err != nil {
		t.Fatal(err)
	}
	return opened{model: c, event: e}
}

func TestRecurrenceExclusionsOverridesAndDST(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Kyiv")
	master := openedText(t, "UID:series\r\nDTSTART;TZID=Europe/Kyiv:20261019T090000\r\nDTEND;TZID=Europe/Kyiv:20261019T100000\r\nRRULE:FREQ=WEEKLY;COUNT=4\r\nEXDATE;TZID=Europe/Kyiv:20261102T090000,20261109T090000\r\nSUMMARY:Standup", loc)
	override := openedText(t, "UID:series\r\nRECURRENCE-ID;TZID=Europe/Kyiv:20261026T090000\r\nDTSTART;TZID=Europe/Kyiv:20261026T103000\r\nDTEND;TZID=Europe/Kyiv:20261026T113000\r\nSUMMARY:Moved", loc)
	from := time.Date(2026, 10, 18, 0, 0, 0, 0, loc)
	to := from.AddDate(0, 1, 0)
	events, err := expand(context.Background(), []opened{master, override}, from, to, loc)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || !strings.Contains(events[0].Start, "09:00:00+03:00") || !strings.Contains(events[1].Start, "10:30:00+02:00") {
		t.Fatal(events)
	}
}

func TestAllDayRecurringAcrossSpringClockChange(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Kyiv")
	e := openedText(t, "UID:day\r\nDTSTART;VALUE=DATE:20260329\r\nDTEND;VALUE=DATE:20260330\r\nRRULE:FREQ=DAILY;COUNT=2", loc)
	events, err := expand(context.Background(), []opened{e}, time.Date(2026, 3, 28, 0, 0, 0, 0, loc), time.Date(2026, 4, 1, 0, 0, 0, 0, loc), loc)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].End != "2026-03-30" || events[1].End != "2026-03-31" {
		t.Fatal(events)
	}
}

func TestBadTimezoneAndDenseRecurrenceFail(t *testing.T) {
	if _, _, err := times("2026-10-12T10:00:00+03:00", "2026-10-12T11:00:00+03:00", "made-up", false, time.UTC); err == nil {
		t.Fatal("unknown timezone accepted")
	}
	e := openedText(t, "UID:dense\r\nDTSTART:20261012T100000Z\r\nDTEND:20261012T110000Z\r\nRRULE:FREQ=SECONDLY", time.UTC)
	if _, err := expand(context.Background(), []opened{e}, time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC), time.UTC); err == nil {
		t.Fatal("dense recurrence accepted")
	}
}

func TestLegacyKyivTimezone(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Kyiv")
	if err != nil {
		t.Fatal(err)
	}
	e := openedText(t, "UID:legacy\r\nDTSTART;TZID=Europe/Kiev:20261019T090000\r\nDTEND;TZID=Europe/Kiev:20261019T100000\r\nRRULE:FREQ=WEEKLY;COUNT=2", loc)
	events, err := expand(context.Background(), []opened{e}, time.Date(2026, 10, 18, 0, 0, 0, 0, loc), time.Date(2026, 10, 28, 0, 0, 0, 0, loc), loc)
	if err != nil || len(events) != 2 {
		t.Fatal(events, err)
	}
	if events[0].Start != "2026-10-19T09:00:00+03:00" || events[1].Start != "2026-10-26T09:00:00+02:00" {
		t.Fatal(events)
	}
}

func TestTimezoneErrorsAreSpecific(t *testing.T) {
	c, err := parseCard("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:bad\r\nDTSTART;TZID=Mars/Olympus:20261019T090000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = span(c, time.UTC)
	if err == nil || !strings.Contains(err.Error(), "Mars/Olympus") || !strings.Contains(err.Error(), "DTSTART") || strings.Contains(err.Error(), "20261019") {
		t.Fatal(err)
	}
}
