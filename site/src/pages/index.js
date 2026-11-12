import React from 'react';
import Layout from '@theme/Layout';
import OperationalCockpit from '@site/src/components/OperationalCockpit';

export default function Home() {
  return (
    <Layout title="Bugterium / OPERATIONAL LENSES" description="Threat intelligence and neural knowledge portal" noFooter={true}>
      <OperationalCockpit defaultLens={null} />
    </Layout>
  );
}
