package store

import "time"

// parseClientSessionInstant compares persisted metadata, not the current writer's
// canonical string representation. Preserve all nine fractional digits. The old
// C server's space-separated SQL timestamps are UTC; RFC3339 timestamps need a zone.
func parseClientSessionInstant(text string) (time.Time, bool) {
	if len(text) < 19 || (text[10] != 'T' && text[10] != ' ') {
		return time.Time{}, false
	}
	base, err := time.Parse("2006-01-02 15:04:05", text[:10]+" "+text[11:19])
	if err != nil || base.Year() < 1 {
		return time.Time{}, false
	}
	position, nanos := 19, 0
	if position < len(text) && text[position] == '.' {
		position++
		digits := 0
		for position < len(text) && text[position] >= '0' && text[position] <= '9' {
			if digits == 9 {
				return time.Time{}, false
			}
			nanos = nanos*10 + int(text[position]-'0')
			digits++
			position++
		}
		if digits == 0 {
			return time.Time{}, false
		}
		for digits < 9 {
			nanos *= 10
			digits++
		}
	}
	offset := 0
	if text[10] == ' ' {
		if position != len(text) {
			return time.Time{}, false
		}
	} else {
		zone := text[position:]
		if zone != "Z" {
			if len(zone) != 6 || (zone[0] != '+' && zone[0] != '-') || zone[3] != ':' {
				return time.Time{}, false
			}
			for _, i := range []int{1, 2, 4, 5} {
				if zone[i] < '0' || zone[i] > '9' {
					return time.Time{}, false
				}
			}
			hours, minutes := int(zone[1]-'0')*10+int(zone[2]-'0'), int(zone[4]-'0')*10+int(zone[5]-'0')
			if hours > 23 || minutes > 59 {
				return time.Time{}, false
			}
			offset = (hours*60 + minutes) * 60
			if zone[0] == '-' {
				offset = -offset
			}
		}
	}
	return base.Add(-time.Duration(offset)*time.Second + time.Duration(nanos)), true
}
