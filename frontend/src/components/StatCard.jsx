function StatCard({
  icon,
  label,
  value,
  description,
}) {
  return (
    <div className="stat-card">
      <div className="stat-card-top">
        <div className="stat-icon">
          {icon}
        </div>
      </div>

      <div className="stat-content">
        <p>{label}</p>
        <strong>{value}</strong>
        <span>{description}</span>
      </div>
    </div>
  );
}

export default StatCard;