// Source of macho-template, a stand-in for the macOS agent: an ad hoc signed Mach-O that holds the two slots the control server fills.
// Built on an Apple silicon Mac with: clang -Os -o macho-template macho-template.c
// The linker signs it ad hoc, as it signs the agent, so sealing must leave every page hash of that signature true.
static volatile const char server_url[] = "ZEDR_SERVER_PLACEHOLDER_URL_DO_NOT_MODIFY_EXACTLY_64_BYTES_LONG";
static volatile const char signing_key[] = "ZEDR_SIGNING_PUBLIC_KEY_PLACEHOLDER_DO_NOT_MODIFY_64_BYTES_LONG";

// Exits 0 only once the control server filled both slots
int main(void) {
    return server_url[0] != 'Z' && signing_key[0] != 'Z' ? 0 : 1;
}
