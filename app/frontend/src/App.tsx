import { useState, useEffect } from 'react';

type User = { id: number; username: string; role: 'user' | 'admin' };

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [adminData, setAdminData] = useState<string | null>(null);

  useEffect(() => {
    // Check session on load
    fetch('/api/me')
      .then(res => {
        if (res.ok) return res.json();
        throw new Error('Unauthorized');
      })
      .then(data => setUser(data))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const handleLogout = async () => {
    await fetch('/api/logout', { method: 'POST' });
    setUser(null);
    setAdminData(null);
  };

  const fetchAdminData = async () => {
    const res = await fetch('/api/admin');
    if (res.ok) {
      const data = await res.json();
      setAdminData(data.message);
    } else {
      setAdminData('Access denied (403)');
    }
  };

  if (loading) return <div className="container">Loading...</div>;

  if (!user) {
    return (
      <div className="container">
        <h1>Bugterium Secure</h1>
        <p>Please sign in to access the portal.</p>
        <a href="/auth/github" className="btn">Login with GitHub</a>
      </div>
    );
  }

  return (
    <div className="container">
      <h1>Dashboard</h1>
      <p>Welcome, <strong>{user.username}</strong>!</p>
      <p>Role: <span className={`badge ${user.role}`}>{user.role}</span></p>
      
      <div style={{ marginTop: '2rem' }}>
        <button onClick={handleLogout} className="btn secondary">Logout</button>
        {user.role === 'admin' && (
          <button onClick={fetchAdminData} className="btn admin">Fetch Admin Data</button>
        )}
      </div>

      {adminData && (
        <div className="admin-panel">
          <h3>Admin Secret</h3>
          <p>{adminData}</p>
        </div>
      )}
    </div>
  );
}

export default App;