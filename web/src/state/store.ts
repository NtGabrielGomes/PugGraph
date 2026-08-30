import { create } from "zustand";
import type { Campaign } from "@/campaign/document";
import { surfaceAttackPaths, type AttackPath } from "@/graph/attackPaths";
import type { Identity } from "@/crypto/identity";
import {
  Session,
  type RecipientSpec,
  type SessionStatus,
} from "@/campaign/session";
import type {
  ChatMessage,
  Claim,
  ClaimIntent,
  Collection,
  Confidence,
  CompromiseLevel,
  Credential,
  CredentialSource,
  CredentialType,
  Detection,
  EdgeKind,
  GraphEdge,
  GraphNode,
  NodeKind,
  NodeTemplate,
  Objective,
  ObjectiveStatus,
  PathMark,
  Provenance,
  RosterEntry,
  SavedFilter,
  Scope,
  Task,
  TaskStatus,
  ThemeOverrides,
} from "@/domain/types";
import { edgePermits } from "@/domain/catalog";
import { unzipSync } from "fflate";
import { importFiles } from "@/io/import";
import { SearchIndex, buildSearchDocs, type SearchFilter, type SearchHit } from "@/graph/search";
import { CampaignRepository, type TimelineEvent } from "@/data/repositories/CampaignRepository";
import * as mutations from "@/state/mutations";

// Re-exported so existing consumers keep importing it from the store.
export type { TimelineEvent };

export type Lens = "all" | "compromised" | "entry" | "ad" | "unconfirmed";

export interface NodeCredentials {
  authenticatesAs: Credential[];
  obtainedHere: Credential[];
  testedHere: Credential[];
}

export const credsForNode = (creds: Credential[], nodeId: string): NodeCredentials => ({
  authenticatesAs: creds.filter((c) => c.belongs_to === nodeId),
  obtainedHere: creds.filter((c) => c.obtained_from === nodeId),
  testedHere: creds.filter((c) => c.tested_against.some((t) => t.host === nodeId)),
});
export type Status = "disconnected" | SessionStatus;

const now = (): number => Date.now();

// Heavy derived state (attack paths + the search index) recomputes this long
// after the last edit/op settles, so it never blocks an interactive mutation.
const DERIVED_DEBOUNCE_MS = 120;

const blankNode = (id: string, label: string, kind: NodeKind, prov: Provenance): GraphNode => ({
  id,
  kind,
  label,
  identity_keys: [{ kind: "hostname", value: label.toLowerCase(), is_primary: true }],
  compromise_level: "unknown",
  fields: {},
  tags: [],
  provenance: prov,
});

export interface FolderTarget {
  saveFolder?: string;
  saveFileName?: string;
}

export interface CreateParams extends FolderTarget {
  identity: Identity;
  campaignId: string;
  recipients: RecipientSpec[];
  seedDemo: boolean;
}

export interface OpenFileParams extends FolderTarget {
  identity: Identity;
  fileBytes: Uint8Array;
}

export type PendingOpenTarget = { kind: "file"; file: File };

export interface NewCredential {
  username: string;
  domain: string;
  credential_type: CredentialType;
  source: CredentialSource;
  secret: string;
  belongs_to?: string;
  obtained_from?: string;
}

interface State {
  session: Session | null;
  campaign: Campaign | null;
  status: Status;
  me: { operatorId: string; displayName: string } | null;
  vaultAvailable: boolean;

  rev: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  credentials: Credential[];
  attackPaths: AttackPath[];
  events: TimelineEvent[];
  messages: ChatMessage[];
  theme: ThemeOverrides;
  roster: RosterEntry[];
  pathmarks: PathMark[];
  positions: Record<string, { x: number; y: number }>;
  collections: Collection[];
  claims: Claim[];
  detections: Detection[];
  tasks: Task[];
  objectives: Objective[];
  scope: Scope;

  highlightPath: string[] | null;
  /** Active pre-built query: the map dims everything outside this scope. */
  queryScope: { label: string; nodeIds: string[]; edgeIds: string[] } | null;
  /** Edge kinds the operator hid from the map (BloodHound-style edge filter).
   * `contains_ou` starts hidden: container nesting is structural noise on an
   * attack map, and big AD imports hairball without this. */
  hiddenEdgeKinds: string[];
  /** BloodHound-style explore: hide the whole map until a search hit, navigator
   * focus, or pre-built query reveals a scope. */
  hideAll: boolean;
  /** Which inspector tab the right column shows. */
  inspectorTab: InspectorTab;
  savedFilters: SavedFilter[];
  nodeTemplates: NodeTemplate[];
  notice: string | null;
  selectedId: string | null;
  lens: Lens;

  filterQuery: string;
  viewAsOf: number | null;

  appearanceOpen: boolean;
  pendingOpen: PendingOpenTarget | null;

  bulkIds: string[];

  createCampaign: (p: CreateParams) => Promise<void>;
  openCampaignFile: (p: OpenFileParams) => Promise<void>;
  exportCampaignFile: () => Uint8Array | null;
  enrollOperator: (spec: RecipientSpec) => void;
  removeOperator: (operatorId: string) => void;
  dismissNotice: () => void;
  leave: () => void;
  attach: (session: Session) => void;
  refresh: () => void;

  select: (id: string | null) => void;
  setLens: (l: Lens) => void;
  setFilterQuery: (q: string) => void;
  saveFilter: (name: string, query: string) => void;
  removeFilter: (id: string) => void;
  saveNodeTemplate: (nodeId: string, name: string) => void;
  removeTemplate: (id: string) => void;
  createFromTemplate: (templateId: string, label: string) => string;
  setViewAsOf: (t: number | null) => void;
  setAppearanceOpen: (v: boolean) => void;
  setPendingOpen: (t: PendingOpenTarget | null) => void;
  setBulkIds: (ids: string[]) => void;
  setHighlightPath: (hops: string[] | null) => void;
  setQueryScope: (q: { label: string; nodeIds: string[]; edgeIds: string[] } | null) => void;
  setInspectorTab: (t: InspectorTab) => void;
  toggleEdgeKind: (kind: string) => void;
  showAllEdgeKinds: () => void;
  toggleHideAll: () => void;
  savePath: (name: string, hops: string[]) => void;
  removePath: (id: string) => void;

  resolveByLabel: (label: string, kind?: NodeKind) => string;
  setCompromise: (id: string, level: CompromiseLevel) => void;
  setLabel: (id: string, label: string) => void;
  setNodeConfidence: (id: string, confidence: Confidence) => void;
  setField: (id: string, key: string, value: unknown) => void;
  removeField: (id: string, key: string) => void;
  addTag: (id: string, tag: string) => void;
  removeTag: (id: string, tag: string) => void;
  addIdentity: (id: string, kind: string, value: string) => void;
  removeNode: (id: string) => void;
  removeEdge: (id: string) => void;
  setEdgeConfidence: (id: string, confidence: Confidence) => void;
  setEdgeField: (id: string, key: string, value: unknown) => void;
  removeEdgeField: (id: string, key: string) => void;
  cloneNode: (id: string) => string;
  bulkSetCompromise: (ids: string[], level: CompromiseLevel) => void;
  bulkAddTag: (ids: string[], tag: string) => void;
  bulkSetField: (ids: string[], key: string, value: unknown) => void;
  bulkRemove: (ids: string[]) => void;
  /** Hard reset: wipe every node, edge and saved position (confirmed in the UI). */
  clearGraph: () => void;
  appendEvent: (action: string, summary: string) => void;

  addCredential: (c: NewCredential) => void;
  setCredentialValidity: (id: string, validity: Credential["validity"]) => void;
  setCredentialLinks: (id: string, belongsTo?: string, obtainedFrom?: string) => void;
  addCredentialTest: (id: string, host: string, succeeded: boolean, note?: string) => void;
  removeCredential: (id: string) => void;
  revealSecret: (id: string) => string | null;

  setThemeColor: (kind: NodeKind, hex?: string) => void;
  setThemeGlyph: (kind: NodeKind, glyph?: NodeKind) => void;
  setThemeVariant: (kind: NodeKind, variant?: string) => void;

  saveNodePositions: (entries: { id: string; x: number; y: number }[]) => void;
  resetLayout: () => void;

  createNode: (kind: NodeKind, label: string, compromise: CompromiseLevel, identity?: { kind: string; value: string }, fields?: Record<string, unknown>) => string;
  createEdge: (source: string, target: string, kind: EdgeKind, confidence: Confidence, fields?: Record<string, unknown>) => void;

  sendMessage: (body: string, ref?: string) => void;
  quickAdd: (input: string) => string;
  importScans: (files: File[]) => void;
  searchEntities: (query: string, filter?: SearchFilter) => SearchHit[];

  // folded collections (lazy materialization of large dumps)
  promoteMember: (collectionId: string, key: string) => string;
  refoldNode: (id: string) => void;

  // collaboration & engagement lifecycle
  claimNode: (id: string, intent: ClaimIntent, note?: string) => void;
  releaseClaim: (id: string) => void;
  logDetection: (d: Omit<Detection, "id" | "operator">) => void;
  removeDetection: (id: string) => void;
  createTask: (title: string, opts?: Partial<Pick<Task, "description" | "assignee" | "priority" | "node_ref" | "phase">>) => void;
  assignTask: (id: string, assignee?: string) => void;
  setTaskStatus: (id: string, status: TaskStatus) => void;
  removeTask: (id: string) => void;
  createObjective: (title: string, opts?: Partial<Pick<Objective, "description" | "owner" | "target_node" | "priority">>) => void;
  setObjectiveStatus: (id: string, status: ObjectiveStatus) => void;
  removeObjective: (id: string) => void;
  setScope: (scope: Scope) => void;
}

const EMPTY_SCOPE: Scope = { in_scope_cidrs: [], out_of_scope_cidrs: [], forbidden_node_ids: [], time_windows: [] };

/** The right-column inspector tabs. Lives here (not in the feature) so any
 * surface — selection, query activation — can steer the inspector. */
export type InspectorTab = "inspect" | "abuse" | "paths" | "vault" | "team";

export const useStore = create<State>((set, get) => {
  const mutate = (fn: (campaign: Campaign, session: Session) => void): void => {
    const { campaign, session } = get();
    if (!campaign || !session)
        return;

    fn(campaign, session);

    session.flush();
    get().refresh();
  };

  const searchIndex = new SearchIndex();

  // Attack paths and the search index are derived projections, expensive to
  // compute. Rather than recompute them inside the synchronous `refresh()` (which
  // runs after every local mutation AND every remote op), schedule them debounced
  // so a keystroke-rate edit stream never blocks on Dijkstra over the whole graph.
  let derivedTimer: ReturnType<typeof setTimeout> | null = null;
  const recomputeDerived = (): void => {
    derivedTimer = null;
    if (!get().campaign) return;
    const { nodes, edges, credentials, events } = get();
    searchIndex.sync(buildSearchDocs(nodes, credentials, events));
    set((s) => ({ attackPaths: surfaceAttackPaths(nodes, edges), rev: s.rev + 1 }));
  };
  const scheduleDerived = (): void => {
    if (derivedTimer) clearTimeout(derivedTimer);
    derivedTimer = setTimeout(recomputeDerived, DERIVED_DEBOUNCE_MS);
  };

  return {
    session: null,
    campaign: null,
    status: "disconnected",
    me: null,
    vaultAvailable: false,

    rev: 0,
    nodes: [],
    edges: [],
    credentials: [],
    attackPaths: [],
    events: [],
    messages: [],
    theme: { colors: {}, glyphs: {}, variants: {} },
    roster: [],
    pathmarks: [],
    positions: {},
    collections: [],
    claims: [],
    detections: [],
    tasks: [],
    objectives: [],
    scope: EMPTY_SCOPE,
    highlightPath: null,
    queryScope: null,
    inspectorTab: "inspect",
    hiddenEdgeKinds: ["contains_ou"],
    hideAll: false,
    savedFilters: [],
    nodeTemplates: [],
    notice: null,
    selectedId: null,
    lens: "all",
    filterQuery: "",
    viewAsOf: null,
    appearanceOpen: false,
    pendingOpen: null,
    bulkIds: [],

    createCampaign: async (p) => {
      const session = await Session.create({
        identity: p.identity,
        campaignId: p.campaignId,
        recipients: p.recipients,
        seedDemo: p.seedDemo,
        saveFolder: p.saveFolder,
        saveFileName: p.saveFileName,
        onChange: () => get().refresh(),
        onStatus: (status) => set({ status }),
        onNotice: (notice) => set({ notice }),
      });
      get().attach(session);
    },

    openCampaignFile: async (p) => {
      const session = await Session.fromFile(
        {
          identity: p.identity,
          campaignId: "",
          saveFolder: p.saveFolder,
          saveFileName: p.saveFileName,
          onChange: () => get().refresh(),
          onStatus: (status) => set({ status }),
          onNotice: (notice) => set({ notice }),
        },
        p.fileBytes,
      );
      get().attach(session);
    },

    exportCampaignFile: () => {
      const { session } = get();
      if (!session)
          return null;
  
      try {
        return session.exportCampaignFile();
      } catch {
        return null;
      }
    },

    enrollOperator: (spec) => {
      const { session } = get();
      if (!session)
          return;

      try {
        session.enrollOperator(spec);
      } catch (e) {
        set({ notice: (e as Error).message });
        return;
      }
      get().refresh();
    },

    removeOperator: (operatorId) => {
      const { session } = get();
      if (!session)
          return;

      try {
        session.removeOperator(operatorId);
      } catch (e) {
        set({ notice: (e as Error).message });
        return;
      }
      get().refresh();
    },

    dismissNotice: () => set({ notice: null }),

    attach: (session) => {
      set({
        session,
        campaign: session.campaign,
        me: { operatorId: session.operatorId, displayName: session.displayName },
        vaultAvailable: session.hasVault(),
        status: "local",
      });
      get().refresh();
    },

    leave: () => {
      get().session?.disconnect();
      if (derivedTimer) {
        clearTimeout(derivedTimer);
        derivedTimer = null;
      }
      set({
        session: null,
        campaign: null,
        status: "disconnected",
        me: null,
        vaultAvailable: false,
        nodes: [],
        edges: [],
        credentials: [],
        attackPaths: [],
        events: [],
        messages: [],
        theme: { colors: {}, glyphs: {}, variants: {} },
        roster: [],
        pathmarks: [],
        positions: {},
        collections: [],
        claims: [],
        detections: [],
        tasks: [],
        objectives: [],
        scope: EMPTY_SCOPE,
        highlightPath: null,
        queryScope: null,
        hideAll: false,
        savedFilters: [],
        nodeTemplates: [],
        filterQuery: "",
        notice: null,
        selectedId: null,
        bulkIds: [],
        appearanceOpen: false,
      });
    },

    refresh: () => {
      const { campaign } = get();
      if (!campaign)
          return;

      // Project the whole read model through the repository (single typed read seam).
      const readModel = new CampaignRepository(campaign).readModel();
      set((s) => ({ rev: s.rev + 1, ...readModel }));
      // Attack paths + search index recompute debounced, off this hot path.
      scheduleDerived();
    },

    select: (id) => {
      set({ selectedId: id });
    },
    setLens: (lens) => set({ lens }),
    setFilterQuery: (filterQuery) => set({ filterQuery }),
    saveFilter: (name, query) => mutate((c, s) => mutations.saveFilter(c, s, name, query)),
    removeFilter: (id) => mutate((c) => c.removeFilter(id)),
    saveNodeTemplate: (nodeId, name) =>
      mutate((c, s) => {
        const n = get().nodes.find((x) => x.id === nodeId);
        if (n) mutations.saveNodeTemplate(c, s, n, name);
      }),
    removeTemplate: (id) => mutate((c) => c.removeTemplate(id)),
    createFromTemplate: (templateId, label) => {
      const { campaign, session } = get();
      if (!campaign || !session)
          return "";

      const t = get().nodeTemplates.find((x) => x.id === templateId);
      if (!t)
          return "";

      const id = mutations.createFromTemplate(campaign, session, t, label);
      session.flush();
      get().refresh();
      get().select(id);
      return id;
    },
    setViewAsOf: (viewAsOf) => set({ viewAsOf }),
    setAppearanceOpen: (appearanceOpen) => set({ appearanceOpen }),
    setPendingOpen: (pendingOpen) => set({ pendingOpen }),
    setBulkIds: (bulkIds) => set({ bulkIds }),
    setHighlightPath: (highlightPath) => set({ highlightPath }),
    setQueryScope: (queryScope) => set({ queryScope }),
    setInspectorTab: (inspectorTab) => set({ inspectorTab }),
    toggleEdgeKind: (kind) =>
      set((s) => ({
        hiddenEdgeKinds: s.hiddenEdgeKinds.includes(kind)
          ? s.hiddenEdgeKinds.filter((k) => k !== kind)
          : [...s.hiddenEdgeKinds, kind],
      })),
    showAllEdgeKinds: () => set({ hiddenEdgeKinds: [] }),
    toggleHideAll: () => set((s) => ({ hideAll: !s.hideAll })),
    savePath: (name, hops) => mutate((c, s) => mutations.savePath(c, s, name, hops)),
    removePath: (id) => mutate((c) => c.removePathMark(id)),

    resolveByLabel: (label, kind = "host_windows") => {
      const { campaign, session } = get();
      if (!campaign || !session)
        return "";

      const existing = get().nodes.find((n) => n.label.toLowerCase() === label.toLowerCase());
      if (existing)
          return existing.id;

      const id = campaign.resolveOrCreate(
        [{ kind: "hostname", value: label.toLowerCase(), is_primary: true }],
        (nid) => blankNode(nid, label, kind, session.provenance()),
      );
      session.flush();
      get().refresh();
      return id;
    },

    setCompromise: (id, level) => mutate((c, s) => mutations.setCompromise(c, s, id, level)),

    setLabel: (id, label) => mutate((c) => c.setLabel(id, label)),
    setNodeConfidence: (id, confidence) => mutate((c) => c.setNodeConfidence(id, confidence)),
    setField: (id, key, value) => mutate((c) => c.setField(id, key, value)),
    removeField: (id, key) => mutate((c) => c.removeField(id, key)),
    addTag: (id, tag) => mutate((c) => c.addTag(id, tag)),
    removeTag: (id, tag) => mutate((c) => c.removeTag(id, tag)),
    addIdentity: (id, kind, value) =>
      mutate((c) => c.addIdentityKey(id, { kind, value, is_primary: false })),
    setEdgeConfidence: (id, confidence) => mutate((c) => c.setEdgeConfidence(id, confidence)),

    removeNode: (id) =>
      mutate((c, s) => {
        mutations.removeNode(c, s, id);
        if (get().selectedId === id) set({ selectedId: null });
      }),
    removeEdge: (id) => mutate((c) => c.removeEdge(id)),
    setEdgeField: (id, key, value) => mutate((c) => c.setEdgeField(id, key, value)),
    removeEdgeField: (id, key) => mutate((c) => c.removeEdgeField(id, key)),

    cloneNode: (id) => {
      const { campaign, session } = get();
      if (!campaign || !session)
        return "";

      const src = get().nodes.find((n) => n.id === id);
      if (!src)
        return "";

      const nid = mutations.cloneNode(campaign, session, src);
      session.flush();
      get().refresh();
      get().select(nid);
      return nid;
    },

    bulkSetCompromise: (ids, level) => mutate((c, s) => mutations.bulkSetCompromise(c, s, ids, level)),
    bulkAddTag: (ids, tag) => mutate((c, s) => mutations.bulkAddTag(c, s, ids, tag)),
    bulkSetField: (ids, key, value) => mutate((c, s) => mutations.bulkSetField(c, s, ids, key, value)),
    bulkRemove: (ids) =>
      mutate((c, s) => {
        mutations.bulkRemove(c, s, ids);
        if (ids.includes(get().selectedId ?? "")) set({ selectedId: null });
      }),

    clearGraph: () =>
      mutate((c, s) => {
        mutations.clearGraph(c, s);
        set({ selectedId: null, bulkIds: [], queryScope: null, highlightPath: null });
      }),

    appendEvent: (action, summary) =>
      mutate((campaign, session) =>
        campaign.appendEvent({ author: session.operatorId, at: now(), action, summary }),
      ),

    addCredential: (input) => mutate((c, s) => mutations.addCredential(c, s, input)),

    setCredentialValidity: (id, validity) =>
      mutate((c) => c.setCredentialValidity(id, validity, now())),
    setCredentialLinks: (id, belongsTo, obtainedFrom) =>
      mutate((c) => c.setCredentialLinks(id, belongsTo || undefined, obtainedFrom || undefined)),
    addCredentialTest: (id, host, succeeded, note) =>
      mutate((c, s) => mutations.addCredentialTest(c, s, id, host, succeeded, note)),
    removeCredential: (id) => mutate((c) => c.removeCredential(id)),

    revealSecret: (id) => {
      const { session } = get();
      const cred = get().credentials.find((c) => c.id === id);
      if (!session || !cred?.secret_sealed)
          return null;

      try {
        return session.openCredentialSecret(cred.secret_sealed);
      } catch {
        return null;
      }
    },

    saveNodePositions: (entries) => mutate((c) => entries.forEach((e) => c.setNodePosition(e.id, e.x, e.y))),
    resetLayout: () => mutate((c) => Object.keys(c.positions()).forEach((id) => c.clearNodePosition(id))),

    setThemeColor: (kind, hex) => mutate((c) => c.setThemeColor(kind, hex)),
    setThemeGlyph: (kind, glyph) => mutate((c) => c.setThemeGlyph(kind, glyph)),
    setThemeVariant: (kind, variant) => mutate((c) => c.setThemeVariant(kind, variant)),

    createNode: (kind, label, compromise, identity, fields) => {
      const { campaign, session } = get();
      if (!campaign || !session)
          return "";

      const id = mutations.createNode(campaign, session, kind, label, compromise, identity, fields);
      session.flush();
      get().refresh();
      get().select(id);
      return id;
    },

    createEdge: (source, target, kind, confidence, fields) => {
      const { campaign, session } = get();
      if (!campaign || !session)
        return;

      const labelOf = (id: string) => get().nodes.find((n) => n.id === id)?.label ?? id;
      const id = mutations.createEdge(campaign, session, source, target, kind, confidence, labelOf, fields);
      session.flush();
      get().refresh();
      get().select(id);
    },

    sendMessage: (body, ref) => mutate((c, s) => mutations.sendMessage(c, s, body, ref)),

    quickAdd: (raw) => {
      const { campaign, session } = get();
      if (!campaign || !session)
        return "";
      
      const input = raw.trim();
      if (!input)
        return "";
      
      const prov = (): Provenance => session.provenance();

      const edgeMatch = input.match(/^(.+?)\s*>\s*(.+?)\s*:\s*(\w+)\s*$/);
      if (edgeMatch) {
        const [, a, b, kind] = edgeMatch;
        const src = get().resolveByLabel(a!.trim());
        const tgt = get().resolveByLabel(b!.trim());
        const ek = kind as GraphEdge["kind"];
        campaign.addEdge({
          id: `${src}|${kind}|${tgt}`,
          kind: ek,
          source: src,
          target: tgt,
          confidence: "confirmed",
          provenance: prov(),
        });
        campaign.appendEvent({ author: session.operatorId, at: now(), action: "edge.add", summary: `${a!.trim()} -[${kind}]-> ${b!.trim()}` });
        session.flush();
        get().refresh();
        const nodes = get().nodes;
        const sk = nodes.find((n) => n.id === src)?.kind;
        const tk = nodes.find((n) => n.id === tgt)?.kind;
        const canonical = sk && tk ? edgePermits(ek, sk, tk) : true;
        const prefix = canonical ? "edge" : `⚠ non-canonical edge (${sk}→${tk})`;
        return `${prefix} ${a!.trim()} →(${kind}) ${b!.trim()}`;
      }

      const compMatch = input.match(/^(.+?)\s*!\s*(\w+)\s*$/);
      if (compMatch) {
        const id = get().resolveByLabel(compMatch[1]!.trim());
        get().setCompromise(id, compMatch[2] as CompromiseLevel);
        return `compromise ${compMatch[1]!.trim()} = ${compMatch[2]}`;
      }

      const tagMatch = input.match(/^(.+?)\s*#\s*(\S+)\s*$/);
      if (tagMatch) {
        const id = get().resolveByLabel(tagMatch[1]!.trim());
        get().addTag(id, tagMatch[2]!);
        return `tag ${tagMatch[1]!.trim()} #${tagMatch[2]}`;
      }

      const nodeMatch = input.match(/^(.+?)(?:\s*:\s*(\w+))?\s*$/);
      const label = nodeMatch![1]!.trim();
      const kind = (nodeMatch![2] as NodeKind) ?? "host_windows";
      get().resolveByLabel(label, kind);
      get().appendEvent("node.upsert", `added ${label} (${kind})`);
      return `node ${label} (${kind})`;
    },

    importScans: (files) => {
      const { campaign, session, me } = get();
      if (!campaign || !session || files.length === 0)
        return;
      
      const author = me?.operatorId ?? "import";
      const seal = session.hasVault() ? (p: string) => session.sealCredentialSecret(p) : undefined;
      void Promise.all(
        files.map(async (f) => {
          // SharpHound ships its collectors as one zip of JSON files — unpack
          // it here so every entry rides the normal text import path.
          if (f.name.toLowerCase().endsWith(".zip")) {
            const entries = unzipSync(new Uint8Array(await f.arrayBuffer()));
            return Object.entries(entries)
              .filter(([name]) => name.toLowerCase().endsWith(".json"))
              .map(([name, bytes]) => ({ name, content: new TextDecoder().decode(bytes) }));
          }
          return [{ name: f.name, content: await f.text() }];
        }),
      ).then((nested) => {
        const inputs = nested.flat();
        const summary = importFiles(campaign, inputs, { author, now: now(), seal });
        campaign.appendEvent({
          author,
          at: now(),
          action: "import",
          summary: `imported ${summary.nodes} node(s), ${summary.edges} edge(s), ${summary.credentials} credential(s)`,
        });
        session.flush();
        get().refresh();
      });
    },

    searchEntities: (query, filter) => searchIndex.search(query, filter),

    // ---- folded collections: lazy materialization ------------------------
    promoteMember: (collectionId, key) => {
      const { campaign, session } = get();
      if (!campaign || !session) return "";
      const id = campaign.promoteMember(collectionId, key, session.provenance());
      if (id) {
        campaign.appendEvent({ author: session.operatorId, at: now(), action: "collection.promote", summary: `materialized ${key} from a collection` });
        session.flush();
        get().refresh();
        get().select(id);
      }
      return id ?? "";
    },
    refoldNode: (id) =>
      mutate((campaign, session) => {
        if (campaign.refoldNode(id, get().edges)) {
          campaign.appendEvent({ author: session.operatorId, at: now(), action: "collection.refold", summary: `refolded ${id}` });
          if (get().selectedId === id) set({ selectedId: null });
        }
      }),

    // ---- collaboration & engagement lifecycle ----------------------------
    claimNode: (id, intent, note) => mutate((c, s) => mutations.claimNode(c, s, id, intent, note)),
    releaseClaim: (id) => mutate((c) => c.releaseClaim(id)),

    logDetection: (d) => mutate((c, s) => mutations.logDetection(c, s, d)),
    removeDetection: (id) => mutate((c) => c.removeDetection(id)),

    createTask: (title, opts) => mutate((c, s) => mutations.createTask(c, s, title, opts)),
    assignTask: (id, assignee) => mutate((c) => c.assignTask(id, assignee, now())),
    setTaskStatus: (id, status) => mutate((c) => c.setTaskStatus(id, status, now())),
    removeTask: (id) => mutate((c) => c.removeTask(id)),

    createObjective: (title, opts) => mutate((c, s) => mutations.createObjective(c, s, title, opts)),
    setObjectiveStatus: (id, status) =>
      mutate((c) => c.setObjectiveStatus(id, status, status === "achieved" ? now() : undefined)),
    removeObjective: (id) => mutate((c) => c.removeObjective(id)),

    setScope: (scope) => mutate((c) => c.setScope(scope)),
  };
});
