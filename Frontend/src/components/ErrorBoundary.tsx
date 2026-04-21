import { Component, type ReactNode } from 'react';
import { AlertTriangle, Home, RotateCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
  onHomeClick: () => void;
}

interface State {
  hasError: boolean;
  error?: Error;
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  handleReset = () => {
    this.setState({ hasError: false, error: undefined });
    this.props.onHomeClick();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex-1 flex flex-col items-center justify-center p-8 gap-6">
          <div className="skeu-card-raised rounded-2xl p-10 max-w-md w-full text-center">
            <div className="w-16 h-16 rounded-2xl skeu-well flex items-center justify-center mx-auto mb-6">
              <AlertTriangle className="w-8 h-8 text-destructive" />
            </div>
            <h2 className="text-xl font-bold text-foreground mb-2">Something went wrong</h2>
            <p className="text-sm text-muted-foreground mb-6">
              {this.state.error?.message || 'An unexpected error occurred. Please return to the control center.'}
            </p>
            <div className="flex gap-3 justify-center">
              <button
                onClick={this.handleReset}
                className="skeu-button-primary rounded-xl px-6 py-3 flex items-center gap-2 text-sm font-medium"
              >
                <Home className="w-4 h-4" />
                Back to Home
              </button>
              <button
                onClick={() => this.setState({ hasError: false })}
                className="skeu-button rounded-xl px-6 py-3 flex items-center gap-2 text-sm font-medium text-muted-foreground"
              >
                <RotateCcw className="w-4 h-4" />
                Retry
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
