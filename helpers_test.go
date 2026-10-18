package capkit_test

import (
	"testing"

	"github.com/c1ayooo/capkit"
)

func TestPageWindowFirstPageAndContinuation(t *testing.T) {
	start, end, page, err := capkit.PageWindow(250, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if start != 0 || end != capkit.MaxListItems {
		t.Fatalf("window = [%d,%d)", start, end)
	}
	if page.Total != 250 || !page.HasMore || page.Cursor == "" {
		t.Fatalf("page = %+v", page)
	}

	// The cursor resumes where the previous page ended.
	start, end, page, err = capkit.PageWindow(250, page.Cursor, 0)
	if err != nil {
		t.Fatal(err)
	}
	if start != capkit.MaxListItems || end != 2*capkit.MaxListItems {
		t.Fatalf("second window = [%d,%d)", start, end)
	}

	// The last page closes the listing.
	start, end, page, err = capkit.PageWindow(250, capkit.CursorFor(200), 0)
	if err != nil {
		t.Fatal(err)
	}
	if start != 200 || end != 250 || page.HasMore || page.Cursor != "" {
		t.Fatalf("last page = [%d,%d) %+v", start, end, page)
	}
}

func TestPageWindowShortListNeedsNoCursor(t *testing.T) {
	start, end, page, err := capkit.PageWindow(3, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if start != 0 || end != 3 || page.Cursor != "" || page.HasMore {
		t.Fatalf("short list = [%d,%d) %+v", start, end, page)
	}
}

func TestPageWindowRejectsBadCursor(t *testing.T) {
	for _, cursor := range []string{"oops", "off:-1", "off:x", "5"} {
		if _, _, _, err := capkit.PageWindow(10, cursor, 0); err == nil {
			t.Errorf("cursor %q: expected an error rather than a silent restart", cursor)
		}
	}
	// An offset at or past the end yields an empty final window, not an error.
	start, end, page, err := capkit.PageWindow(10, capkit.CursorFor(10), 0)
	if err != nil {
		t.Fatal(err)
	}
	if start != 10 || end != 10 || page.HasMore {
		t.Fatalf("past-end window = [%d,%d) %+v", start, end, page)
	}
}

func TestFirstNonEmptyAndPositive(t *testing.T) {
	if got := capkit.FirstNonEmpty("", "  ", "\t", "x", "y"); got != "x" {
		t.Fatalf("FirstNonEmpty = %q", got)
	}
	if got := capkit.FirstNonEmpty("", " "); got != "" {
		t.Fatalf("FirstNonEmpty = %q", got)
	}
	if got := capkit.FirstPositive(0, 7); got != 7 {
		t.Fatalf("FirstPositive = %d", got)
	}
	if got := capkit.FirstPositive(3, 7); got != 3 {
		t.Fatalf("FirstPositive = %d", got)
	}
}

func TestPreviewRunesCountsCharactersNotBytes(t *testing.T) {
	// 300 Chinese characters: a byte-based cut would split a rune and report more
	// than 200 characters, which §5.5.4 forbids.
	s := ""
	for i := 0; i < 300; i++ {
		s += "测"
	}
	got := capkit.PreviewRunes(s, 200)
	if n := len([]rune(got)); n != 200 {
		t.Fatalf("preview = %d runes, want 200", n)
	}
	if capkit.PreviewRunes("short", 200) != "short" {
		t.Fatal("a short preview must pass through unchanged")
	}
}
