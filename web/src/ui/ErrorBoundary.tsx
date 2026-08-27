import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  /** Short label for what failed, shown in the fallback. */
  label: string;
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/** Isolates a render crash to one panel: a thrown error in a child degrades to a
 * recoverable in-place fallback instead of white-screening the whole workspace
 * mid-engagement. "Reset panel" clears the error so the subtree re-mounts. */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Operator-facing console trail; this handler must never itself throw.
    console.error(`[${this.props.label}] panel crashed:`, error, info.componentStack);
  }

  private reset = (): void => this.setState({ error: null });

  render(): ReactNode {
    const { error } = this.state;
    if (error) {
      return (
        <div className="panelerror" role="alert">
          <strong>{this.props.label} failed</strong>
          <span className="panelerror-msg">{error.message || "Unexpected error"}</span>
          <button type="button" className="ghost small" onClick={this.reset}>
            Reset panel
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
