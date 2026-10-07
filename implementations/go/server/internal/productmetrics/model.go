// Package productmetrics implements opt-in product metrics (protocol/spec/product-metrics.md):
// a per-tenant switch an ADMIN turns on after acknowledging the disclosure, onboarding
// milestones the server observes on its own write paths, transfer outcomes the sending browser
// reports with five closed-enum fields, daily counters only, a retention sweep, a purge and the
// summary read API. Nothing here stores or logs credentials, file names, text, addresses or any
// identifier of a room, device or visitor.
package productmetrics

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion     = 1
	DisclosureVersion = 1
	RetentionDays     = 180
	WindowDays        = 14
	MaxBodyBytes      = 4096
	MaxEvents         = 20
	MaxRangeDays      = 180

	DefaultPerUserEventsPerMinute   = 120
	DefaultPerTenantEventsPerMinute = 3000

	CodeInvalid            = "PRODUCT_METRICS_INVALID"
	CodeTooLarge           = "PRODUCT_METRICS_TOO_LARGE"
	CodeRateLimited        = "PRODUCT_METRICS_RATE_LIMITED"
	CodeDisclosureRequired = "PRODUCT_METRICS_DISCLOSURE_REQUIRED"
	CodeRange              = "PRODUCT_METRICS_RANGE"
	CodeNotAllowed         = "PRODUCT_METRICS_NOT_ALLOWED"
	CodeUnavailable        = "PRODUCT_METRICS_UNAVAILABLE"

	dayMs    = int64(24 * time.Hour / time.Millisecond)
	windowMs = WindowDays * dayMs
)

// Onboarding steps in order; the index is the step number minus one.
const (
	StepAccountCreated    = "account_created"
	StepSignedIn          = "signed_in"
	StepCredentialCreated = "credential_created"
	StepClientOnline      = "client_online"
	StepServicePublished  = "service_published"
)

var (
	Steps    = []string{StepAccountCreated, StepSignedIn, StepCredentialCreated, StepClientOnline, StepServicePublished}
	Modes    = []string{"device", "link"}
	Paths    = []string{"direct", "turn", "cloud", "unestablished"}
	Attempts = []string{"first", "retry_after_failure", "retry_after_cancel"}
	Outcomes = []string{"success", "failure", "cancelled"}
	// SizeBuckets in order; see SizeBucket for the bounds.
	SizeBuckets = []string{"lt1m", "1m-16m", "16m-128m", "128m-512m", "gt512m"}
	// DurationBuckets in order; see DurationBucket for the bounds.
	DurationBuckets = []string{"lt10m", "10m-30m", "30m-2h", "2h-24h", "1d-3d", "3d-14d"}
)

// NoDuration is the duration bucket of an onboarding row closed without completing.
const NoDuration = "none"

const mib = int64(1) << 20

var durationUpperBounds = []int64{600, 1800, 7200, 86400, 259200, WindowDays * 86400}

// SizeBucket returns the bucket of a file size in bytes; an empty or negative size has none,
// because the browser never reports an empty file.
func SizeBucket(size int64) (string, bool) {
	switch {
	case size < 1:
		return "", false
	case size < mib:
		return "lt1m", true
	case size < 16*mib:
		return "1m-16m", true
	case size <= 128*mib:
		return "16m-128m", true
	case size <= 512*mib:
		return "128m-512m", true
	default:
		return "gt512m", true
	}
}

// DurationBucket returns the completion-time bucket of seconds (negative counts as zero); at or
// past the window there is none, because such a row expired instead of completing.
func DurationBucket(seconds int64) (string, bool) {
	if seconds < 0 {
		seconds = 0
	}
	for index, upper := range durationUpperBounds {
		if seconds < upper {
			return DurationBuckets[index], true
		}
	}
	return "", false
}

// RateBp is numerator/denominator in basis points rounded half up, or nil without a denominator.
func RateBp(numerator, denominator int64) *int64 {
	if denominator == 0 {
		return nil
	}
	rate := (20000*numerator + denominator) / (2 * denominator)
	return &rate
}

// Event is one reported transfer attempt: exactly the five closed fields.
type Event struct {
	Mode       string
	Path       string
	SizeBucket string
	Attempt    string
	Outcome    string
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (e Event) valid() bool {
	if !contains(Modes, e.Mode) || !contains(Paths, e.Path) || !contains(SizeBuckets, e.SizeBucket) ||
		!contains(Attempts, e.Attempt) || !contains(Outcomes, e.Outcome) {
		return false
	}
	if e.Mode == "link" && e.Path != "cloud" && e.Path != "unestablished" {
		return false
	}
	return !(e.Outcome == "success" && e.Path == "unestablished")
}

var errInvalid = errors.New("invalid product metrics request")

// ParseIngest validates a transfer-outcome request body against the closed schema of section 7.4
// and returns its events, or the refusal code. The size is checked on the raw bytes first. Any
// extra, missing or duplicated key, any value of the wrong JSON type and any trailing content
// rejects the whole request: there is no path that ignores an unknown field.
func ParseIngest(body []byte) ([]Event, string) {
	if len(body) > MaxBodyBytes {
		return nil, CodeTooLarge
	}
	events, err := parseIngest(body)
	if err != nil {
		return nil, CodeInvalid
	}
	return events, ""
}

func parseIngest(body []byte) ([]Event, error) {
	if !utf8.Valid(body) {
		return nil, errInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := expectDelim(decoder, '{'); err != nil {
		return nil, err
	}
	var events []Event
	seenVersion, seenEvents := false, false
	for decoder.More() {
		key, err := objectKey(decoder)
		if err != nil {
			return nil, err
		}
		switch {
		case key == "schemaVersion" && !seenVersion:
			seenVersion = true
			token, err := decoder.Token()
			if err != nil {
				return nil, errInvalid
			}
			if number, ok := token.(json.Number); !ok || number.String() != "1" {
				return nil, errInvalid
			}
		case key == "events" && !seenEvents:
			seenEvents = true
			if events, err = parseEvents(decoder); err != nil {
				return nil, err
			}
		default:
			return nil, errInvalid
		}
	}
	if err := expectDelim(decoder, '}'); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errInvalid
	}
	if !seenVersion || !seenEvents {
		return nil, errInvalid
	}
	return events, nil
}

func parseEvents(decoder *json.Decoder) ([]Event, error) {
	if err := expectDelim(decoder, '['); err != nil {
		return nil, err
	}
	events := make([]Event, 0, MaxEvents)
	for decoder.More() {
		if len(events) == MaxEvents {
			return nil, errInvalid
		}
		event, err := parseEvent(decoder)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := expectDelim(decoder, ']'); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, errInvalid
	}
	return events, nil
}

func parseEvent(decoder *json.Decoder) (Event, error) {
	if err := expectDelim(decoder, '{'); err != nil {
		return Event{}, err
	}
	var event Event
	fields := map[string]*string{"mode": &event.Mode, "path": &event.Path, "sizeBucket": &event.SizeBucket,
		"attempt": &event.Attempt, "outcome": &event.Outcome}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := objectKey(decoder)
		if err != nil {
			return Event{}, err
		}
		target, known := fields[key]
		if !known || seen[key] {
			return Event{}, errInvalid
		}
		seen[key] = true
		token, err := decoder.Token()
		if err != nil {
			return Event{}, errInvalid
		}
		text, ok := token.(string)
		if !ok {
			return Event{}, errInvalid
		}
		*target = text
	}
	if err := expectDelim(decoder, '}'); err != nil {
		return Event{}, err
	}
	if len(seen) != len(fields) || !event.valid() {
		return Event{}, errInvalid
	}
	return event, nil
}

func objectKey(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", errInvalid
	}
	key, ok := token.(string)
	if !ok {
		return "", errInvalid
	}
	return key, nil
}

func expectDelim(decoder *json.Decoder, delim json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return errInvalid
	}
	if found, ok := token.(json.Delim); !ok || found != delim {
		return errInvalid
	}
	return nil
}

// SettingsUpdate is a validated PUT /settings body.
type SettingsUpdate struct {
	Enabled bool
	// Disclosure is the acknowledged disclosure version; nil when the body omits it.
	Disclosure *string
}

// ParseSettingsUpdate validates the closed PUT body: enabled (boolean, required) and
// disclosureVersion (integer, optional); anything else is invalid.
func ParseSettingsUpdate(body []byte) (SettingsUpdate, bool) {
	if !utf8.Valid(body) {
		return SettingsUpdate{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if expectDelim(decoder, '{') != nil {
		return SettingsUpdate{}, false
	}
	var update SettingsUpdate
	seenEnabled := false
	for decoder.More() {
		key, err := objectKey(decoder)
		if err != nil {
			return SettingsUpdate{}, false
		}
		token, err := decoder.Token()
		if err != nil {
			return SettingsUpdate{}, false
		}
		switch {
		case key == "enabled" && !seenEnabled:
			value, ok := token.(bool)
			if !ok {
				return SettingsUpdate{}, false
			}
			update.Enabled, seenEnabled = value, true
		case key == "disclosureVersion" && update.Disclosure == nil:
			number, ok := token.(json.Number)
			if !ok || !integerLiteral(number.String()) {
				return SettingsUpdate{}, false
			}
			text := number.String()
			update.Disclosure = &text
		default:
			return SettingsUpdate{}, false
		}
	}
	if expectDelim(decoder, '}') != nil {
		return SettingsUpdate{}, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return SettingsUpdate{}, false
	}
	return update, seenEnabled
}

// integerLiteral reports whether a JSON number is written as an integer (no fraction, no exponent).
func integerLiteral(text string) bool {
	if text == "" {
		return false
	}
	for index, character := range text {
		if character == '-' && index == 0 {
			continue
		}
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// Day is the UTC calendar date of an instant.
func Day(at time.Time) string {
	return at.UTC().Format("2006-01-02")
}

// DayOfMillis is the UTC calendar date of an epoch-millisecond instant.
func DayOfMillis(ms int64) string {
	return Day(time.UnixMilli(ms))
}

// Instant renders an epoch-millisecond instant to the second, as the contract's examples do.
func Instant(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05Z")
}
