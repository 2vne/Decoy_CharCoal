import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Unhandled React Error in Component Tree:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[50vh] flex flex-col items-center justify-center p-6 text-center font-mono">
          <div className="p-5 rounded-lg bg-red-950/40 border border-red-500/50 max-w-2xl w-full space-y-3 shadow-xl text-left">
            <div className="flex items-center space-x-2 text-red-400 font-bold text-sm">
              <AlertTriangle className="h-5 w-5" />
              <span>UI Component Render Issue Detected</span>
            </div>
            <div className="p-3 rounded bg-black/60 border border-red-900/50 text-xs text-red-200 overflow-x-auto whitespace-pre-wrap font-mono">
              {String(this.state.error?.stack || this.state.error?.message || this.state.error)}
            </div>
            <div className="pt-2 flex justify-end">
              <button
                onClick={this.handleReset}
                className="px-4 py-1.5 rounded bg-red-900 hover:bg-red-800 text-white text-xs font-semibold flex items-center space-x-2 transition"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                <span>Reload Dashboard</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

