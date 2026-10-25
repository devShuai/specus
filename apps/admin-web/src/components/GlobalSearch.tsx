import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { Icon, type IconName } from "./ui/Icon";

export interface SearchEntry {
  key: string;
  title: string;
  /** Shown under the title: the group or what the entry does. */
  subtitle: string;
  icon: IconName;
  /** Extra words that should find the entry. */
  keywords?: string;
  run: () => void;
}

/**
 * The topbar search of the design (SearchBox in the glass topbar): finds pages and common actions.
 * "/" or Ctrl/⌘ K focuses it; arrow keys move through the results and Enter opens one.
 */
export function GlobalSearch({ entries, searching, onSearchingChange }: {
  entries: SearchEntry[];
  /** Phones show the box only while searching. */
  searching: boolean;
  onSearchingChange: (searching: boolean) => void;
}) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const listId = useId();

  const results = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return entries;
    return entries.filter((entry) =>
      `${entry.title} ${entry.subtitle} ${entry.keywords ?? ""} ${entry.key}`.toLowerCase().includes(needle));
  }, [entries, query]);

  useEffect(() => { setActiveIndex(0); }, [query]);

  useEffect(() => {
    const onKey = (event: globalThis.KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing = target && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName));
      if ((event.key === "k" && (event.metaKey || event.ctrlKey)) || (event.key === "/" && !typing)) {
        event.preventDefault();
        onSearchingChange(true);
        inputRef.current?.focus();
        setOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onSearchingChange]);

  useEffect(() => {
    if (searching) inputRef.current?.focus();
  }, [searching]);

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    window.addEventListener("pointerdown", onPointer);
    return () => window.removeEventListener("pointerdown", onPointer);
  }, [open]);

  const choose = (entry: SearchEntry | undefined) => {
    if (!entry) return;
    entry.run();
    setQuery("");
    setOpen(false);
    onSearchingChange(false);
    inputRef.current?.blur();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setOpen(true);
      setActiveIndex((index) => Math.min(results.length - 1, index + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((index) => Math.max(0, index - 1));
    } else if (event.key === "Enter") {
      event.preventDefault();
      choose(results[activeIndex]);
    } else if (event.key === "Escape") {
      if (query) setQuery("");
      else { setOpen(false); onSearchingChange(false); inputRef.current?.blur(); }
    }
  };

  const showList = open && results.length >= 0;
  return (
    <div className="jd-search" ref={rootRef}>
      <div className="jd-search-box">
        <Icon name="search" size={18} />
        <input
          ref={inputRef}
          className="jd-search-input"
          type="search"
          role="combobox"
          aria-label="搜索页面与操作"
          aria-expanded={showList}
          aria-controls={listId}
          aria-activedescendant={showList && results[activeIndex] ? `${listId}-${results[activeIndex].key}` : undefined}
          aria-autocomplete="list"
          autoComplete="off"
          placeholder="搜索页面与操作"
          value={query}
          onChange={(event) => { setQuery(event.target.value); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onKeyDown={onKeyDown}
        />
        {query ? (
          <button type="button" className="jd-search-clear" aria-label="清空搜索" onClick={() => { setQuery(""); inputRef.current?.focus(); }}>
            <Icon name="x" size={12} />
          </button>
        ) : (
          <kbd className="app-search-kbd" aria-hidden="true">/</kbd>
        )}
      </div>
      <button type="button" className="jd-search-cancel" onClick={() => { setQuery(""); setOpen(false); onSearchingChange(false); }}>
        取消
      </button>
      {showList ? (
        <div className="bd-popover app-search-results" role="listbox" id={listId} aria-label="搜索结果">
          {results.length === 0 ? (
            <div className="jd-sg-empty">没有匹配的页面或操作</div>
          ) : results.map((entry, index) => (
            <div
              key={entry.key}
              id={`${listId}-${entry.key}`}
              role="option"
              aria-selected={index === activeIndex}
              className={`jd-sg-row${index === activeIndex ? " is-active" : ""}`}
              onPointerEnter={() => setActiveIndex(index)}
              onPointerDown={(event) => event.preventDefault()}
              onClick={() => choose(entry)}
            >
              <span className="jd-sg-icon"><Icon name={entry.icon} /></span>
              <span className="jd-sg-text">
                <span className="jd-sg-name">{entry.title}</span>
                <span className="jd-sg-sub">{entry.subtitle}</span>
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
