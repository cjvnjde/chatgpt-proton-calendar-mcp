package mcpserver

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"proton-calendar-mcp/internal/calendar"
)

func addCalendarTools(s *mcp.Server, service *calendar.Service, read, write *mcp.ToolAnnotations) {
	mcp.AddTool(s, &mcp.Tool{Name: "capabilities", Description: "Read the deployed MCP version, implemented operations, and remaining limitations before planning calendar actions. Do not infer feature support from Proton's own UI.", Annotations: read}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return nil, map[string]any{
			"version":            Version,
			"supported":          []string{"personal_event_create_read_update_delete", "recurring_event_create_read", "recurring_occurrence_delete_including_stored_exceptions", "recurring_series_delete_all_or_future", "proton_guest_creation_via_calendar_sync", "organizer_guest_event_update_without_email", "organizer_guest_event_delete_without_email", "calendar_create_and_key_setup", "https_calendar_subscription_create", "calendar_membership_settings", "calendar_default_duration_and_reminders", "calendar_delete", "proton_calendar_sharing_and_access_changes", "public_calendar_links_create_read_revoke", "event_or_complete_series_ics_export", "basic_personal_ics_import_with_new_uids", "event_change_polling"},
			"unsupported":        []string{"invitation_update_cancellation_email_delivery", "external_guest_creation", "existing_event_guest_add_remove", "invitation_rsvp", "recurring_occurrence_reschedule", "recurring_future_edit_or_series_split", "cross_calendar_moves", "accept_calendar_sharing_invitation", "full_fidelity_ics_import", "whole_calendar_export", "holiday_calendar_management", "booking_pages", "video_conferencing", "native_push_scheduling"},
			"validation":         "Synthetic protocol and cryptographic tests. New operations still require live-account validation; this is not full Proton Calendar parity.",
			"cancellation_email": "Never sent by this version; send_cancellation_notice=true is rejected.",
		}, nil
	})

	mcp.AddTool(s, &mcp.Tool{Name: "addresses_list", Description: "List your account's sending address IDs and email addresses. Does not expose keys.", Annotations: read}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		r, e := service.Addresses(ctx)
		return nil, map[string]any{"addresses": r}, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_get", Description: "Read an allowed calendar's membership, default reminders and duration, and revision for calendar administration.", Annotations: read}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.CalendarInput) (*mcp.CallToolResult, calendar.CalendarDetails, error) {
		r, e := service.CalendarGet(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_update", Description: "Change your calendar's name, description, color, or visibility. Omitted fields are preserved. Requires the revision from calendar_get.", Annotations: write}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.CalendarUpdateInput) (*mcp.CallToolResult, calendar.CalendarDetails, error) {
		r, e := service.CalendarUpdate(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_settings_update", Description: "Change calendar default duration, timed/all-day reminders, and whether events show as busy. Omitted fields are preserved; empty reminder lists disable defaults. Requires the calendar_get revision.", Annotations: write}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.CalendarSettingsInput) (*mcp.CallToolResult, calendar.CalendarDetails, error) {
		r, e := service.CalendarSettingsUpdate(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_create", Description: "Create and initialize an encrypted calendar, optionally subscribed to an HTTPS ICS feed fetched by Proton. Requires an address from addresses_list and a stable request_id. A fixed calendar allowlist prevents creation. Uncertain or incomplete creation is never automatically replayed.", Annotations: write}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.CalendarCreateInput) (*mcp.CallToolResult, calendar.CalendarCreateResult, error) {
		r, e := service.CalendarCreate(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_delete", Description: "Permanently delete an owned calendar and ALL its events. Requires the exact name and revision from calendar_get. This is calendar removal, not an event cancellation notice. Proton may require interactive reauthentication; no passwords are accepted here.", Annotations: write}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.CalendarDeleteInput) (*mcp.CallToolResult, calendar.CalendarCreateResult, error) {
		r, e := service.CalendarDelete(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_members", Description: "List active members and sharing invitations for an allowed calendar, with a revision for access changes.", Annotations: read}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.CalendarInput) (*mcp.CallToolResult, calendar.MembersResult, error) {
		r, e := service.CalendarMembers(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_share", Description: "Grant a Proton user access to an entire calendar by sending a sharing invitation and encrypting the calendar sharing key to their Proton public key. viewer reads events; editor can modify them. Only do this when sharing with that recipient is explicitly requested. This may notify the recipient.", Annotations: write}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.CalendarShareInput) (*mcp.CallToolResult, calendar.CalendarCreateResult, error) {
		r, e := service.CalendarShare(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_access_update", Description: "Change or revoke an existing member's or pending invitee's calendar access. Requires the calendar_members revision. Owners and this account's own membership cannot be changed here.", Annotations: write}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.CalendarAccessInput) (*mcp.CallToolResult, calendar.CalendarCreateResult, error) {
		r, e := service.CalendarAccessUpdate(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_links", Description: "List public calendar links without revealing their usable URLs. A separate calendar_link_get call exposes the link credential.", Annotations: read}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.CalendarInput) (*mcp.CallToolResult, calendar.PublicLinksResult, error) {
		r, e := service.PublicLinks(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_link_create", Description: "Publish a calendar as an ICS URL. Anyone holding a full-access URL can read event details, and Proton can decrypt the exported feed. Limited links reveal free/busy only. Only call when the user explicitly requests publishing/sharing this calendar. Do not blindly retry an uncertain create.", Annotations: write}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.LinkCreateInput) (*mcp.CallToolResult, calendar.PublicLink, error) {
		r, e := service.PublicLinkCreate(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_link_get", Description: "Retrieve the usable URL for a public calendar link. The URL grants access; only reveal it when requested.", Annotations: read}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.LinkInput) (*mcp.CallToolResult, calendar.PublicLink, error) {
		r, e := service.PublicLinkGet(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "calendar_link_delete", Description: "Revoke one public calendar link without deleting the calendar or its events.", Annotations: write}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.LinkInput) (*mcp.CallToolResult, calendar.CalendarCreateResult, error) {
		r, e := service.PublicLinkDelete(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "event_export", Description: "Export a stored event as plaintext ICS. A recurring master exports its full verified series, including exceptions outside the displayed date range. Guest details are included. No data is sent to another service.", Annotations: read}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.ExportInput) (*mcp.CallToolResult, calendar.ExportResult, error) {
		r, e := service.Export(ctx, in)
		return nil, r, e
	})
	mcp.AddTool(s, &mcp.Tool{Name: "events_import", Description: "Import up to 100 confirmed personal VEVENTs as new events with new UIDs. Supports ordinary fields and RRULE; guests, exclusions, stored exceptions, custom VTIMEZONE and alarms are refused, never silently dropped. The entire document is validated first. Remote failures may leave a partial import: inspect complete, events and failed_index. Reuse the same request_id and arguments to resume acknowledged creates safely.", Annotations: write}, func(ctx context.Context, _ *mcp.CallToolRequest, in calendar.ImportInput) (*mcp.CallToolResult, calendar.ImportResult, error) {
		r, e := service.Import(ctx, in)
		return nil, r, e
	})

}
