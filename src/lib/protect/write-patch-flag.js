module.exports = writePatchFlag;

const debug = require('debug')('snyk');
const fs = require('fs');
const path = require('path');

function writePatchFlag(now, vuln) {
  if (!vuln) {
    vuln = now;
    now = new Date();
  }

  debug('writing flag for %s', vuln.id);
  // the colon doesn't like Windows, ref: https://git.io/vw2iO
  const fileSafeId = vuln.id.replace(/:/g, '-');
  const flag = path.resolve(vuln.source, '.snyk-' + fileSafeId + '.flag');
  if (vuln.grouped && vuln.grouped.includes) {
    debug('found addition vulns to write flag files for');
    fs.writeFileSync(flag, now.toJSON(), 'utf8');
    vuln.grouped.includes.forEach(() => {
      const fileSafeId = vuln.id.replace(/:/g, '-');
      const flag = path.resolve(vuln.source, '.snyk-' + fileSafeId + '.flag');
      debug('Writing flag for grouped vulns', flag);
      fs.writeFileSync(flag, now.toJSON(), 'utf8');
    });
  } else {
    debug('Writing flag for single vuln', flag);
    fs.writeFileSync(flag, now.toJSON(), 'utf8');
  }
  return vuln;
}
