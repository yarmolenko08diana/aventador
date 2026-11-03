import { Component, type ReactNode } from "react";

// Ошибка в одной странице (например, в графике) не должна оставлять пустой экран
export default class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-800">
          <p className="font-medium">Страница не отрисовалась из-за ошибки в интерфейсе.</p>
          <pre className="mt-2 whitespace-pre-wrap text-xs">{this.state.error.message}</pre>
          <button className="btn-secondary mt-3" onClick={() => this.setState({ error: null })}>Попробовать снова</button>
        </div>
      );
    }
    return this.props.children;
  }
}
