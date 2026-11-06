import React from 'react';
import Layout from '@theme/Layout';
import SecurityDashboard from '../components/SecurityDashboard';

export default function MonitorPage() {
  return (
    <Layout title="Security Monitor" description="Live Threat Intelligence">
      <div className="container margin-vert--lg">
        <SecurityDashboard />
      </div>
    </Layout>
  );
}