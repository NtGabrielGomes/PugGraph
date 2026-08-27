// Repository pattern: the single typed READ seam over the Loro campaign document.
// The store (and, through it, components) projects state via one `readModel()` call
// instead of reaching into `Campaign`/`Session` internals across dozens of sites — so
// the CRDT surface can evolve behind a stable contract, and reads are trivially
// mockable in tests.

import type { Campaign } from "@/campaign/document";
import type {
  ChatMessage,
  Claim,
  Collection,
  Credential,
  Detection,
  GraphEdge,
  GraphNode,
  NodeTemplate,
  Objective,
  PathMark,
  RosterEntry,
  SavedFilter,
  Scope,
  ThemeOverrides,
  Task,
} from "@/domain/types";

/** An entry in the append-only activity log (author/time/action/summary). */
export interface TimelineEvent {
  author: string;
  at: number;
  action: string;
  summary: string;
}

/** Everything the store projects from the document in one pass. */
export interface CampaignReadModel {
  nodes: GraphNode[];
  edges: GraphEdge[];
  credentials: Credential[];
  events: TimelineEvent[];
  messages: ChatMessage[];
  theme: ThemeOverrides;
  roster: RosterEntry[];
  pathmarks: PathMark[];
  positions: Record<string, { x: number; y: number }>;
  savedFilters: SavedFilter[];
  nodeTemplates: NodeTemplate[];
  collections: Collection[];
  claims: Claim[];
  detections: Detection[];
  tasks: Task[];
  objectives: Objective[];
  scope: Scope;
}

export class CampaignRepository {
  constructor(private readonly campaign: Campaign) {}

  /** Project the whole read model the store holds, in one place. */
  readModel(): CampaignReadModel {
    const c = this.campaign;
    return {
      nodes: c.nodes(),
      edges: c.edges(),
      credentials: c.credentials(),
      events: c.events() as TimelineEvent[],
      messages: c.messages(),
      theme: c.theme(),
      roster: c.roster(),
      pathmarks: c.pathmarks(),
      positions: c.positions(),
      savedFilters: c.filters(),
      nodeTemplates: c.templates(),
      collections: c.collections(),
      claims: c.claims(),
      detections: c.detections(),
      tasks: c.tasks(),
      objectives: c.objectives(),
      scope: c.scope(),
    };
  }
}
