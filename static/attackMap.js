// =======================================
// LayerSeven Neon Attack Beam Renderer
// =======================================

// Severity colors
const severityColors = {
    critical: "#ff0033",
    high: "#ff6600",
    medium: "#00ffff",
    low: "#00ccff"
};

// Draw glowing beam
function drawAttackBeam(map, fromCoords, toCoords, severity = "medium") {

    const color = severityColors[severity] || "#00ffff";

    // Glow layer (soft neon aura)
    L.polyline([fromCoords, toCoords], {
        color: color,
        weight: 10,
        opacity: 0.15,
        interactive: false
    }).addTo(map);

    // Main beam line
    L.polyline([fromCoords, toCoords], {
        color: color,
        weight: 2,
        opacity: 0.9,
        interactive: false
    }).addTo(map);

    // Animate packet flow
    animatePacket(map, fromCoords, toCoords, color);
}


// Animate packet moving along beam
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
        }
    }

    movePacket();
}