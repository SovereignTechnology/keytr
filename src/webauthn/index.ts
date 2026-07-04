export { checkCapabilities, checkPrfSupport, ensureBrowser } from './support.js'
export { registerPasskey } from './register.js'
export { authenticatePasskey, kihAuthenticatePasskey, discoverPasskey } from './authenticate.js'
export {
  prfRegistrationExtension,
  prfAuthenticationExtension,
  extractPrfOutput,
  isPrfEnabled,
} from './prf.js'
export { extractKey, detectMode } from './kih.js'
export { parseBackupFlags } from './flags.js'
export {
  signalUnknownCredential,
  signalAllAcceptedCredentialIds,
  signalCurrentUserDetails,
} from './signal.js'
