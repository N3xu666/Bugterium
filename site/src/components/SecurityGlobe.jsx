import React, { useEffect, useRef } from 'react';
import Globe from 'react-globe.gl';
import { countryCoords } from './countryCoords';

export default function SecurityGlobe({ geoData }) {
  const globeEl = useRef();

  // Преобразуем коды стран в координаты для точек
  const pointsData = geoData
    .filter(item => countryCoords[item.country] && item.country !== 'XX')
    .map(item => ({
      lat: countryCoords[item.country][0],
      lng: countryCoords[item.country][1],
      size: Math.log(item.count + 1) * 0.05, // Логарифмический масштаб, чтобы точки не были гигантскими
      color: '#ff8c00', // Наш оранжевый цвет
      name: item.country,
      count: item.count
    }));

  useEffect(() => {
    // Автоматическое вращение глобуса
    if (globeEl.current) {
      globeEl.current.controls().autoRotate = true;
      globeEl.current.controls().autoRotateSpeed = 1.5;
    }
  }, []);

  return (
    <div style={{ cursor: 'grab', height: '500px', width: '100%' }}>
      <Globe
        ref={globeEl}
        globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg" // Темная текстура
        backgroundColor="rgba(0,0,0,0)" // Прозрачный фон (чтобы видеть тему сайта)
        atmosphereColor="#a855f7" // Фиолетовое свечение
        atmosphereAltitude={0.15}
        pointsData={pointsData}
        pointAltitude={0.05}
        pointRadius="size"
        pointColor="color"
        pointLabel={({ name, count }) => `<b>${name}</b>: ${count} requests`}
        ringsData={pointsData}
        ringColor={() => '#ff8c00'} // Оранжевые пульсирующие кольца
        ringMaxRadius="size"
        ringPropagationSpeed={2}
        ringRepeatPeriod={1000}
      />
    </div>
  );
}