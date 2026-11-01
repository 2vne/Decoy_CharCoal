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
          <div className="p-4 rounded-lg bg-red-950/40 border border-red-500/50 max-w-lg w-full space-y-3 shadow-xl">
            <div className="flex items-center justify-center space-x-2 text-red-400 font-bold text-sm">
              <AlertTriangle className="h-5 w-5" />
              <span>UI Component Render Issue Detected</span>
            </div>
            <p className="text-xs text-slate-300">
              {this.state.error?.message || 'An unexpected rendering error occurred in this view.'}
            </p>
            <div className="pt-2 flex justify-center">
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
