import {
  CheckCircle2,
  CircleDot,
  Loader2,
  Square,
} from "lucide-react";

function PipelineStep({
  label,
  message,
  progress,
  currentProgress,
  status,
  isCancelled = false,
}) {
  const cancelled = status === "cancelled" || isCancelled;
  const completed = status === "completed" && !cancelled;
  const running = status === "running" && !cancelled;

  const active =
    !cancelled &&
    !completed &&
    !running &&
    currentProgress >= progress;

  let stateClass = "";

  if (cancelled) {
    stateClass = "cancelled";
  } else if (completed) {
    stateClass = "completed";
  } else if (running) {
    stateClass = "running";
  } else if (active) {
    stateClass = "active";
  }

  let displayText = "Waiting";
  let displayProgress = `${progress}%`;

  if (cancelled) {
    displayText = "Cancelled";
    displayProgress = "✕";
  } else if (completed) {
    displayText = "Complete";
    displayProgress = "✓";
  } else if (running) {
    displayText = message;
    displayProgress = `${Math.round(currentProgress)}%`;
  } else if (active) {
    displayText = "Processing...";
    displayProgress = `${Math.round(currentProgress)}%`;
  }

  return (
    <div className={`pipeline-step ${stateClass}`}>
      <div className="pipeline-step-icon">
        {completed ? (
          <CheckCircle2 size={16} />
        ) : running ? (
          <Loader2 size={16} className="spin" />
        ) : cancelled ? (
          <Square size={16} />
        ) : (
          <CircleDot size={16} />
        )}
      </div>

      <div className="pipeline-step-content">
        <strong>{label}</strong>
        <span>{displayText}</span>
      </div>

      <div className="pipeline-step-progress">
        {displayProgress}
      </div>
    </div>
  );
}

export default PipelineStep;