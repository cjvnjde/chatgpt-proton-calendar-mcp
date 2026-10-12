package calendar

import (
	"context"
	"strings"
	"testing"
)

func TestPersonalImportReplayExportAndValidation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:old@example.test\r\nDTSTAMP:20261012T060000Z\r\nDTSTART:20261012T070000Z\r\nDTEND:20261012T080000Z\r\nSUMMARY:Imported\r\nRRULE:FREQ=DAILY;COUNT=2\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	in := ImportInput{CalendarID: "calendar1", RequestID: "import-1", ICS: ics}
	result, err := f.service.Import(ctx, in)
	if err != nil || !result.Complete || len(result.Events) != 1 {
		t.Fatal(result, err)
	}
	if f.writes != 1 {
		t.Fatal(f.writes)
	}
	repeat, err := f.service.Import(ctx, in)
	if err != nil || !repeat.Complete || !repeat.Events[0].Replayed || f.writes != 1 {
		t.Fatal("duplicate import", repeat, err)
	}
	exported, err := f.service.Export(ctx, ExportInput{"calendar1", "event1"})
	if err != nil || !strings.Contains(exported.ICS, "SUMMARY:Imported") || !strings.Contains(exported.ICS, "RRULE:FREQ=DAILY;COUNT=2") {
		t.Fatal(exported, err)
	}
	changed := in
	changed.ICS = strings.ReplaceAll(ics, "Imported", "Changed")
	if _, err := f.service.Import(ctx, changed); err == nil {
		t.Fatal("changed import request accepted")
	}
	in.RequestID = "invalid"
	in.ICS = strings.ReplaceAll(ics, "SUMMARY:Imported", "SUMMARY:Imported\r\nATTENDEE:mailto:guest@example.test")
	if _, err := f.service.Import(ctx, in); err == nil {
		t.Fatal("guest invitation silently converted")
	}
	if f.writes != 1 {
		t.Fatal("invalid import issued writes")
	}
}
