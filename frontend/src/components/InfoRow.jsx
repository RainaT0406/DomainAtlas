function InfoRow({ label, value }) {
  return (
    <div className="info-row">
      <div className="info-label">
        <span className="info-marker" />
        {label}
      </div>

      <span className="info-value">
        {value}
      </span>
    </div>
  );
}

export default InfoRow;