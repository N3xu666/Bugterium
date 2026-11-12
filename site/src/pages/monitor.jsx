import React from 'react';
import Layout from '@theme/Layout';
import OperationalCockpit from '@site/src/components/OperationalCockpit';

export default function MonitorPage() {
  return (
    <Layout title="Bugterium / SECURITY MONITOR" description="Live Threat Intelligence" noFooter={true}>
      <OperationalCockpit defaultLens="globe" />
    </Layout>
  );
}
