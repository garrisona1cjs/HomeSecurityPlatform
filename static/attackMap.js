// =======================================
// LayerSeven Neon Attack Beam Renderer
// FULL VERSION
// =======================================

// Severity colors for beams
const severityColors = {
    critical: "#ff0033",
    high: "#ff6600",
    medium: "#00ffff",
    low: "#00ccff"
};

// prevent duplicate origin pulses
let activeOrigins = {};

// ================================
// 🟢 ORIGIN PULSE GLOW
// ================================
function createOriginPulse(map, location) {

    const key = location.toString();
    if (activeOrigins[key]) return; // prevent stacking

    const pulseColor = "#00ff88";   // neon green

    // bright center dot
    const center = L.circleMarker(location, {
        radius: 8,
        color: pulseColor,
        fillColor: pulseColor,
        fillOpacity: 1
    }).addTo(map);

    // expanding ring
    const ring = L.circle(location, {
        radius: 20000,
        color: pulseColor,
        weight: 2,
        opacity: 0.7,
        fillOpacity: 0
    }).addTo(map);

    let radius = 20000;
    let opacity = 0.7;

    function animatePulse() {
        radius += 1200;
        opacity -= 0.015;

        ring.setRadius(radius);
        ring.setStyle({ opacity: opacity });

        if (opacity <= 0) {
            radius = 20000;
            opacity = 0.7;
        }

        requestAnimationFrame(animatePulse);
    }

    animatePulse();

    activeOrigins[key] = true;
}


// ================================
// 💥 IMPACT FLASH + SHOCKWAVE
// ================================
function createImpactFlash(map, location, color) {

    const flash = L.circleMarker(location, {
        radius: 8,
        color: color,
        fillColor: color,
        fillOpacity: 0.9
    }).addTo(map);

    const ring = L.circle(location, {
        radius: 20000,
        color: color,
        weight: 2,
        opacity: 0.6,
        fillOpacity: 0
    }).addTo(map);

    let opacity = 0.9;
    let radius = 20000;

    function animateImpact() {

        opacity -= 0.05;
        radius += 20000;

        flash.setStyle({ fillOpacity: opacity, opacity: opacity });
        ring.setStyle({ opacity: opacity });
        ring.setRadius(radius);

        if (opacity > 0) {
            requestAnimationFrame(animateImpact);
        } else {
            map.removeLayer(flash);
            map.removeLayer(ring);
        }
    }

    animateImpact();
}


// ================================
// ⚡ PACKET MOVEMENT
// ================================
function animatePacket(map, from, to, color) {

    let progress = 0;

    const packet = L.circleMarker(from, {
        radius: 4,
        color: color,
        fillColor: color,
        fillOpacity: 1
    }).addTo(map);

    function movePacket() {

        progress += 0.02;

        const lat = from[0] + (to[0] - from[0]) * progress;
        const lng = from[1] + (to[1] - from[1]) * progress;

        packet.setLatLng([lat, lng]);

        if (progress < 1) {
            requestAnimationFrame(movePacket);
        } else {
            map.removeLayer(packet);
            createImpactFlash(map, to, color);
        }
    }

    movePacket();
}


// ================================
// 🔥 DRAW NEON ATTACK BEAM
// ================================
function drawAttackBeam(map, fromCoords, toCoords, severity = "medium") {

    const color = severityColors[severity] || "#00ffff";

    // 🟢 origin pulse
    createOriginPulse(map, fromCoords);

    // glow aura
    L.polyline([fromCoords, toCoords], {
        color: color,
        weight: 3,
        opacity: 0.05,
        interactive: false
    }).addTo(map);

    // main beam
    L.polyline([fromCoords, toCoords], {
        color: color,
        weight: 1,
        opacity: 1,
        interactive: false
    }).addTo(map);

    // moving packet
    animatePacket(map, fromCoords, toCoords, color);

    // 🌊 flowing particle stream
    createBeamTrail(map, fromCoords, toCoords, color);
}


// ================================
// 🌊 BEAM TRAIL PARTICLE STREAM
// ================================
function createBeamTrail(map, from, to, color) {

    const particles = [];
    const particleCount = 10;

    for (let i = 0; i < particleCount; i++) {
        particles.push({
            progress: Math.random()
        });
    }

    function animateParticles() {

        particles.forEach(p => {

            p.progress += 0.02;

            if (p.progress > 1) {
                p.progress = 0;
            }

            const lat = from[0] + (to[0] - from[0]) * p.progress;
            const lng = from[1] + (to[1] - from[1]) * p.progress;

            const dot = L.circleMarker([lat, lng], {
                radius: 1.5,
                color: color,
                fillColor: color,
                fillOpacity: 0.8,
                interactive: false
            }).addTo(map);

            setTimeout(() => map.removeLayer(dot), 180);
        });

        requestAnimationFrame(animateParticles);
    }

    animateParticles();
}