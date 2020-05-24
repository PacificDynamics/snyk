import * as _ from 'lodash';

import * as YAML from 'js-yaml';

const mandatoryKeysForSupportedK8sKinds = {
  deployment: ['apiVersion', 'metadata', 'spec'],
  pod: ['apiVersion', 'metadata', 'spec'],
  service: ['apiVersion', 'metadata', 'spec'],
};

function getFileType(filePath: string): string {
  const filePathSplit = filePath.split('.');
  return filePathSplit[filePathSplit.length - 1].toLowerCase();
}

function parseYamlOrJson(
  fileContent: string,
  filePath: string,
  logContext: any,
): any {
  const fileType = getFileType(filePath);
  switch (fileType) {
    case 'yaml':
    case 'yml':
      try {
        return YAML.safeLoadAll(fileContent);
      } catch (e) {
        // logger.warn(
        //   { ...logContext, targetFile: filePath, err: e.message },
        //   'Failed to parse cloud config as a YAML',
        // );
      }
      break;
    case 'json':
      try {
        const objectsArr: any[] = [];
        objectsArr.push(JSON.parse(fileContent));
        return objectsArr;
      } catch (e) {
        // logger.warn(
        //   { ...logContext, targetFile: filePath, err: e },
        //   'Failed to parse cloud config as a JSON',
        // );
      }
      break;
    default:
    // logger.error(
    //   { ...logContext, filePath },
    //   'Unsupported cloud config file type',
    // );
  }
  return undefined;
}

// This function validates that there is at least one valid doc with a k8s object kind.
// A valid k8s object has a kind key (.kind) from the keys of `mandatoryKeysForSupportedK8sKinds`
// and all of the keys from `mandatoryKeysForSupportedK8sKinds[kind]`.
// If there is a doc with a supported kind, but invalid, we should fail
// The function return true if the yaml is a valid k8s one, or false otherwise
export function isValidK8sFile(
  fileContent: string,
  filePath: string,
  logContext: any,
): boolean {
  const k8sObjects: any[] = parseYamlOrJson(fileContent, filePath, logContext);
  if (!k8sObjects) {
    return false;
  }

  let numOfSupportedKeyDocs = 0;
  for (let i = 0; i < k8sObjects.length; i++) {
    const k8sObject = k8sObjects[i];
    if (!k8sObject || !k8sObject.kind) {
      continue;
    }

    const kind = k8sObject.kind.toLowerCase();
    if (!Object.keys(mandatoryKeysForSupportedK8sKinds).includes(kind)) {
      continue;
    }

    numOfSupportedKeyDocs++;

    for (let i = 0; i < mandatoryKeysForSupportedK8sKinds[kind].length; i++) {
      const key = mandatoryKeysForSupportedK8sKinds[kind][i];
      if (!k8sObject[key]) {
        // logger.error(
        //   { ...logContext, targetFile: filePath },
        //   'Missing key from supported k8s object kind',
        // );
        return false;
      }
    }
  }

  if (numOfSupportedKeyDocs === 0) {
    return false;
  }

  // logger.info({ ...logContext, targetFile: filePath }, 'k8s config found');
  return true;
}
