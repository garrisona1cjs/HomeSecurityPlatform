// =======================================
// LayerSeven Neon Attack Beam Renderer
// WITH Impact Flash + Origin Pulse
// =======================================

// Severity colors
const severityColors = {
    critical: "#ff0033",
    high: "#ff6600",
    medium: "#00ffff",
    low: "#00ccff"
};

// Track active origin pulses
let activeOrigins = {};

// Draw glowing beam
function drawAttackBeam(map, fromCoords, toCoords, severity = "medium") {

    const color = severityColors[severity] || "#00ffff";

    // ORIGIN PULSE
    createOriginPulse(map, fromCoords, color);

    // Glow aura beam
    L.polyline([fromCoords, toCoords], {
        color: color,
        weight: 10,
        opacity: 0.15,
        interactive: false
    }).addTo(map);

    // Main beam
    L.polyline([fromCoords, toCoords], {
        color: color,
        weight: 2,
        opacity: 0.9,
        interactive: false
    }).addTo(map);

    // Animate packet
    animatePacket(map, fromCoords, toCoords, color);
}


// 🟢 ORIGIN PULSE GLOW
function createOriginPulse(map, location, color) {

    const key = location.toString();

    // Prevent stacking pulses on same origin
    if (activeOrigins[key]) return;

    const pulse = L.circleMarker(location, {
        radius: 6,
        color: color,
        fillColor: color,
        fillOpacity: 0.8
    }).addTo(map);

    const ring = L.circle(location, {
        radius: 15000,
        color: color,
        weight: 2,
        opacity: 0.5,
        fillOpacity: 0
    }).addTo(map);

    let radius = 15000;
    let opacity = 0.5;

    function animatePulse() {

        radius += 1000;
        opacity -= 0.01;

        ring.setRadius(radius);
        ring.setStyle({ opacity: opacity });

        if (opacity <= 0) {
            radius = 15000;
            opacity = 0.5;
        }

        requestAnimationFrame(animatePulse);
    }

    animatePulse();

    activeOrigins[key] = true;
}


// Animate packet movement
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


// 💥 Impact flash + shockwave
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