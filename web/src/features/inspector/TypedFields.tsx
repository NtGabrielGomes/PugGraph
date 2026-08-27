import { useState } from "react";
import type { FieldDef } from "@/domain/fieldSchema";
import { Icon, Select } from "@/ui";

export function TypedField({
  fieldKey,
  def,
  value,
  onCommit,
}: {
  fieldKey: string;
  def: FieldDef;
  value: unknown;
  onCommit: (v: unknown | undefined) => void;
}) {
  const commit = (v: unknown) => {
    if (v === "" || v === undefined || (Array.isArray(v) && v.length === 0))
        onCommit(undefined);
    else
        onCommit(v);
  };
  const k = fieldKey;

  if (def.type === "bool") {
    return (
      <label className="tf bool">
        <input type="checkbox" checked={value === true} onChange={(e) => commit(e.target.checked ? true : undefined)} />
        <span>{def.label}</span>
      </label>
    );
  }
  if (def.type === "enum") {
    return (
      <label className="tf">
        <span>{def.label}</span>
        <Select
          ariaLabel={def.label}
          value={typeof value === "string" ? value : ""}
          onChange={(v) => commit(v || undefined)}
          options={[{ value: "", label: "—" }, ...def.enumValues!.map((v) => ({ value: v, label: v }))]}
        />
      </label>
    );
  }
  if (def.type === "multiline") {
    return (
      <label className="tf wide">
        <span>{def.label}</span>
        <textarea key={k} defaultValue={typeof value === "string" ? value : ""} placeholder={def.placeholder} rows={2} onBlur={(e) => commit(e.target.value.trim())} />
      </label>
    );
  }
  if (def.type === "number") {
    return (
      <label className="tf">
        <span>{def.label}</span>
        <input key={k} type="number" defaultValue={typeof value === "number" ? String(value) : ""} onBlur={(e) => commit(e.target.value === "" ? undefined : Number(e.target.value))} />
      </label>
    );
  }
  if (def.type === "tags") {
    const arr = Array.isArray(value) ? (value as unknown[]).map(String) : [];
    return (
      <label className="tf wide">
        <span>{def.label}</span>
        <input
          key={k}
          defaultValue={arr.join(", ")}
          placeholder={def.placeholder ?? "comma-separated"}
          onBlur={(e) => {
            const parts = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
            commit(parts.length ? parts : undefined);
          }}
        />
      </label>
    );
  }
  return (
    <label className="tf">
      <span>{def.label}</span>
      <input key={k} defaultValue={typeof value === "string" ? value : value != null ? String(value) : ""} placeholder={def.placeholder} onBlur={(e) => commit(e.target.value.trim())} />
    </label>
  );
}

export function TypedFields({
  ownerId,
  fields,
  schema,
  onSet,
  onRemove,
}: {
  ownerId: string;
  fields: Record<string, unknown>;
  schema: FieldDef[];
  onSet: (key: string, value: unknown) => void;
  onRemove: (key: string) => void;
}) {
  const groups = [...new Set(schema.map((f) => f.group))]
    .sort((a, b) => (a === "Compromise" ? -1 : b === "Compromise" ? 1 : 0));
  return (
    <>
      {groups.map((g) => {
        const fieldsIn = schema.filter((f) => f.group === g);
        const showHeader = !(fieldsIn.length === 1 && fieldsIn[0]!.label === g);
        return (
          <div className="field" key={g}>
            {showHeader && <span>{g}</span>}
            <div className="tfgrid">
              {fieldsIn.map((f) => (
                <TypedField
                  key={f.key}
                  fieldKey={`${ownerId}:${f.key}`}
                  def={f}
                  value={fields[f.key]}
                  onCommit={(v) => (v === undefined ? onRemove(f.key) : onSet(f.key, v))}
                />
              ))}
            </div>
          </div>
        );
      })}
    </>
  );
}

// Progressive disclosure for the create dialogs: nothing is shown by default —
// the operator adds only the details they care about, picked from a grouped menu
// (the grouping is the recommendation). Keeps the create form short and calm.
export function ProgressiveFields({
  draftKey,
  schema,
  values,
  onChange,
}: {
  draftKey: string;
  schema: FieldDef[];
  values: Record<string, unknown>;
  onChange: (key: string, value: unknown | undefined) => void;
}) {
  const [shown, setShown] = useState<string[]>([]);
  if (schema.length === 0)
      return null;

  const shownDefs = shown
    .map((k) => schema.find((f) => f.key === k))
    .filter((f): f is FieldDef => !!f);
  const remaining = schema.filter((f) => !shown.includes(f.key));
  const groups = [...new Set(remaining.map((f) => f.group))];
  const options = groups.map((g) => ({
    label: g,
    options: remaining.filter((f) => f.group === g).map((f) => ({ value: f.key, label: f.label })),
  }));

  const drop = (key: string) => {
    setShown((s) => s.filter((k) => k !== key));
    onChange(key, undefined);
  };

  return (
    <div className="addfields">
      {shownDefs.map((f) => (
        <div className="addfield" key={f.key}>
          <TypedField
            fieldKey={`${draftKey}:${f.key}`}
            def={f}
            value={values[f.key]}
            onCommit={(v) => onChange(f.key, v)}
          />
          <button type="button" className="x" title="Remove field" onClick={() => drop(f.key)}>
            <Icon name="close" size={13} />
          </button>
        </div>
      ))}
      {remaining.length > 0 && (
        <Select
          value=""
          placeholder="+ Add detail"
          ariaLabel="Add an optional field"
          options={options}
          onChange={(v) => v && setShown((s) => [...s, v])}
        />
      )}
    </div>
  );
}

