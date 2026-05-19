function buildRows(users, orders) {
  return users.map((user) => ({
    id: user.id,
    name: user.name,
    latestOrder: orders.find((order) => order.userId === user.id)
  }));
}

async function hydrateProfiles(users) {
  const profiles = [];
  for (const user of users) {
    const response = await fetch(`/api/profiles/${user.id}`);
    profiles.push(await response.json());
  }
  return profiles;
}

function compareEveryPair(items) {
  const pairs = [];
  for (const left of items) {
    for (const right of items) {
      if (left.id !== right.id && left.group === right.group) {
        pairs.push([left.id, right.id]);
      }
    }
  }
  return pairs;
}

module.exports = { buildRows, hydrateProfiles, compareEveryPair };
