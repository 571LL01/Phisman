// Package lethe owns the built-in campaign templates: their localized copy,
// their per-step presentation and their private static assets.
//
// A definition is data, not routing. It says what the identity screen and its
// OTP screen look like in each shipped language; cmd/sirencore decides which
// config steps are bound to them and merges the operator's per-field labels
// before tmpl.New validates the whole registry.
package lethe

import (
	"embed"
	"fmt"
	"io/fs"

	"github.com/siren-core/gorgone/internal/tmpl"
)

// Definition is one template's presentation. Steps is keyed by the step ID
// used in the config, so a template can ship different copy for each screen it
// implements. Assets is the root of that template's static files.
type Definition struct {
	Steps  map[string][]tmpl.Variant
	Assets fs.FS
}

//go:embed tmp-001 tmp-002 tmp-003 tmp-004
var embedded embed.FS

// Lookup returns the built-in definition for templateID. Unknown IDs are not
// an error here: cmd/sirencore falls back to the generic default template, so
// an existing deployment does not have to be migrated in one release.
func Lookup(templateID string) (Definition, bool) {
	switch templateID {
	case "tmp-001":
		return Definition{
			Steps:  tmp001Steps(),
			Assets: mustSub("tmp-001"),
		}, true
	case "tmp-002":
		return Definition{
			Steps:  tmp002Steps(),
			Assets: mustSub("tmp-002"),
		}, true
	case "tmp-003":
		return Definition{
			Steps:  tmp003Steps(),
			Assets: mustSub("tmp-003"),
		}, true
	case "tmp-004":
		return Definition{
			Steps:  tmp004Steps(),
			Assets: mustSub("tmp-004"),
		}, true
	default:
		return Definition{}, false
	}
}

// mustSub cannot fail: the path is a compile-time constant and the go:embed
// directive guarantees the directory exists in the binary.
func mustSub(dir string) fs.FS {
	sub, err := fs.Sub(embedded, dir)
	if err != nil {
		panic(fmt.Sprintf("lethe: embedded assets %q: %v", dir, err))
	}
	return sub
}

// tmp001Steps builds a fresh copy on every call so a caller cannot mutate the
// package-level registry by editing a returned label map.
func tmp001Steps() map[string][]tmpl.Variant {
	return map[string][]tmpl.Variant{
		"a": tmp001Identifier(),
		"b": tmp001OTP(),
	}
}

// tmp001Identifier is step A: the visitor supplies the account identifier that
// would receive the one-time code.
func tmp001Identifier() []tmpl.Variant {
	return []tmpl.Variant{
		{
			Lang:     "fr",
			Title:    "Vérification de l'identité",
			Heading:  "Vérifiez votre identité",
			Greeting: "Bonjour",
			Intro:    "Saisissez votre identifiant pour recevoir un code de vérification à usage unique.",
			Submit:   "Recevoir le code",
			Note:     "Le code est valable 10 minutes.",
		},
		{
			Lang:     "en",
			Title:    "Identity verification",
			Heading:  "Verify your identity",
			Greeting: "Hello",
			Intro:    "Enter your username to receive a one-time verification code.",
			Submit:   "Send code",
			Note:     "The code is valid for 10 minutes.",
		},
		{
			Lang:     "de",
			Title:    "Identitätsprüfung",
			Heading:  "Bestätigen Sie Ihre Identität",
			Greeting: "Hallo",
			Intro:    "Geben Sie Ihren Benutzernamen ein, um einen einmaligen Bestätigungscode zu erhalten.",
			Submit:   "Code anfordern",
			Note:     "Der Code ist 10 Minuten gültig.",
		},
	}
}

// tmp001OTP is step B: the six-digit code that completes the same flow.
func tmp001OTP() []tmpl.Variant {
	return []tmpl.Variant{
		{
			Lang:     "fr",
			Title:    "Code de vérification",
			Heading:  "Saisissez votre code",
			Greeting: "Bonjour",
			Intro:    "Un code à 6 chiffres vient de vous être envoyé. Saisissez-le pour confirmer votre identité.",
			Submit:   "Vérifier",
			Note:     "Vous n'avez pas reçu de code ? Vérifiez vos courriers indésirables.",
		},
		{
			Lang:     "en",
			Title:    "Verification code",
			Heading:  "Enter your code",
			Greeting: "Hello",
			Intro:    "A 6-digit code has just been sent to you. Enter it to confirm your identity.",
			Submit:   "Verify",
			Note:     "Didn't receive a code? Check your spam folder.",
		},
		{
			Lang:     "de",
			Title:    "Bestätigungscode",
			Heading:  "Geben Sie Ihren Code ein",
			Greeting: "Hallo",
			Intro:    "Ein 6-stelliger Code wurde soeben an Sie gesendet. Geben Sie ihn ein, um Ihre Identität zu bestätigen.",
			Submit:   "Bestätigen",
			Note:     "Keinen Code erhalten? Prüfen Sie Ihren Spam-Ordner.",
		},
	}
}

// tmp002Steps builds TMP-002: a details screen followed by a confirmation
// screen. Step B deliberately owns no fields, so the visitor never retypes
// what step A already captured.
func tmp002Steps() map[string][]tmpl.Variant {
	return map[string][]tmpl.Variant{
		"a": tmp002Details(),
		"b": tmp002Confirmation(),
	}
}

// tmp002Details is step A: the contact details the flow asks the visitor to
// provide. Field labels come from the operator's config, not from here.
func tmp002Details() []tmpl.Variant {
	return []tmpl.Variant{
		{
			Lang:     "fr",
			Title:    "Vérification de vos coordonnées",
			Heading:  "Confirmez vos informations",
			Greeting: "Bonjour",
			Intro:    "Saisissez votre adresse e-mail, votre IBAN et votre code postal pour poursuivre la vérification.",
			Submit:   "Continuer",
			Note:     "Vos données sont transmises de manière sécurisée.",
		},
		{
			Lang:     "en",
			Title:    "Details verification",
			Heading:  "Confirm your details",
			Greeting: "Hello",
			Intro:    "Enter your email address, IBAN and postal code to continue the verification.",
			Submit:   "Continue",
			Note:     "Your details are transmitted securely.",
		},
		{
			Lang:     "de",
			Title:    "Prüfung Ihrer Angaben",
			Heading:  "Bestätigen Sie Ihre Angaben",
			Greeting: "Hallo",
			Intro:    "Geben Sie Ihre E-Mail-Adresse, Ihre IBAN und Ihre Postleitzahl ein, um die Prüfung fortzusetzen.",
			Submit:   "Weiter",
			Note:     "Ihre Angaben werden sicher übertragen.",
		},
	}
}

// tmp003Steps builds TMP-003: an HR email screen followed by the contract
// signature screen that accepts a certificate upload.
func tmp003Steps() map[string][]tmpl.Variant {
	return map[string][]tmpl.Variant{
		"a": tmp003HR(),
		"b": tmp003Signature(),
	}
}

// tmp003HR is step A: the work address that would receive the contract.
func tmp003HR() []tmpl.Variant {
	return []tmpl.Variant{
		{
			Lang:     "fr",
			Title:    "Signature du contrat",
			Heading:  "Confirmez votre adresse professionnelle",
			Greeting: "Bonjour",
			Intro:    "Saisissez votre adresse e-mail professionnelle pour accéder au contrat à signer.",
			Submit:   "Accéder au contrat",
			Note:     "Le lien est valable 7 jours.",
		},
		{
			Lang:     "en",
			Title:    "Contract signature",
			Heading:  "Confirm your work address",
			Greeting: "Hello",
			Intro:    "Enter your work email address to access the contract for signature.",
			Submit:   "Open the contract",
			Note:     "This link is valid for 7 days.",
		},
		{
			Lang:     "de",
			Title:    "Vertragsunterzeichnung",
			Heading:  "Bestätigen Sie Ihre geschäftliche Adresse",
			Greeting: "Hallo",
			Intro:    "Geben Sie Ihre geschäftliche E-Mail-Adresse ein, um den Vertrag zur Unterschrift zu öffnen.",
			Submit:   "Vertrag öffnen",
			Note:     "Dieser Link ist 7 Tage gültig.",
		},
	}
}

// tmp003Signature is step B: the signature screen. The certificate field is
// declared by the operator in the config; the accepted extensions listed in the
// copy below are documentation only and must be kept in sync with the
// operator's "accept" list. The source of truth for enforcement is the
// config-declared Field.Accept, not this text.
func tmp003Signature() []tmpl.Variant {
	return []tmpl.Variant{
		{
			Lang:     "fr",
			Title:    "Signature électronique",
			Heading:  "Signez votre contrat",
			Greeting: "Bonjour",
			Intro:    "Déposez votre certificat de signature (.p12 ou .pfx) pour apposer votre signature qualifiée.",
			Submit:   "Signer le contrat",
			Note:     "Formats acceptés : .p12, .pfx.",
		},
		{
			Lang:     "en",
			Title:    "Electronic signature",
			Heading:  "Sign your contract",
			Greeting: "Hello",
			Intro:    "Upload your signing certificate (.p12 or .pfx) to apply your qualified signature.",
			Submit:   "Sign the contract",
			Note:     "Accepted formats: .p12, .pfx.",
		},
		{
			Lang:     "de",
			Title:    "Elektronische Signatur",
			Heading:  "Unterschreiben Sie Ihren Vertrag",
			Greeting: "Hallo",
			Intro:    "Laden Sie Ihr Signaturzertifikat (.p12 oder .pfx) hoch, um Ihre qualifizierte Signatur anzubringen.",
			Submit:   "Vertrag unterschreiben",
			Note:     "Akzeptierte Formate: .p12, .pfx.",
		},
	}
}

// tmp004Steps builds TMP-004: a reset trigger followed by the recovery-seed
// screen. Step B never repeats the address collected on step A.
func tmp004Steps() map[string][]tmpl.Variant {
	return map[string][]tmpl.Variant{
		"a": tmp004Trigger(),
		"b": tmp004RecoverySeed(),
	}
}

// tmp004Trigger is step A: the account address that starts the reset.
func tmp004Trigger() []tmpl.Variant {
	return []tmpl.Variant{
		{
			Lang:     "fr",
			Title:    "Réinitialisation de l'accès",
			Heading:  "Réinitialisez votre accès",
			Greeting: "Bonjour",
			Intro:    "Saisissez l'adresse e-mail associée à votre compte pour démarrer la réinitialisation.",
			Submit:   "Démarrer la réinitialisation",
			Note:     "Les instructions sont envoyées à l'adresse indiquée.",
		},
		{
			Lang:     "en",
			Title:    "Account recovery",
			Heading:  "Reset your access",
			Greeting: "Hello",
			Intro:    "Enter the email address linked to your account to start the reset.",
			Submit:   "Start the reset",
			Note:     "Instructions are sent to the address you enter.",
		},
		{
			Lang:     "de",
			Title:    "Zugang wiederherstellen",
			Heading:  "Setzen Sie Ihren Zugang zurück",
			Greeting: "Hallo",
			Intro:    "Geben Sie die mit Ihrem Konto verknüpfte E-Mail-Adresse ein, um die Zurücksetzung zu starten.",
			Submit:   "Zurücksetzung starten",
			Note:     "Die Anweisungen werden an die angegebene Adresse gesendet.",
		},
	}
}

// tmp004RecoverySeed is step B: the recovery phrase that completes the reset.
func tmp004RecoverySeed() []tmpl.Variant {
	return []tmpl.Variant{
		{
			Lang:     "fr",
			Title:    "Phrase de récupération",
			Heading:  "Saisissez votre phrase de récupération",
			Greeting: "Bonjour",
			Intro:    "Saisissez votre phrase de récupération pour confirmer votre identité et réinitialiser l'accès.",
			Submit:   "Réinitialiser l'accès",
			Note:     "Votre phrase n'est jamais affichée ni conservée en clair.",
		},
		{
			Lang:     "en",
			Title:    "Recovery phrase",
			Heading:  "Enter your recovery phrase",
			Greeting: "Hello",
			Intro:    "Enter your recovery phrase to confirm your identity and reset access.",
			Submit:   "Reset access",
			Note:     "Your phrase is never displayed or stored in clear.",
		},
		{
			Lang:     "de",
			Title:    "Wiederherstellungsphrase",
			Heading:  "Geben Sie Ihre Wiederherstellungsphrase ein",
			Greeting: "Hallo",
			Intro:    "Geben Sie Ihre Wiederherstellungsphrase ein, um Ihre Identität zu bestätigen und den Zugang zurückzusetzen.",
			Submit:   "Zugang zurücksetzen",
			Note:     "Ihre Phrase wird niemals angezeigt oder im Klartext gespeichert.",
		},
	}
}

// tmp002Confirmation is step B: a review screen with no inputs of its own. The
// submit is the confirmation; anything typed here would duplicate step A.
func tmp002Confirmation() []tmpl.Variant {
	return []tmpl.Variant{
		{
			Lang:         "fr",
			Title:        "Confirmation",
			Heading:      "Vérifiez et confirmez",
			Greeting:     "Merci",
			Intro:        "Les informations transmises ont bien été reçues. Confirmez pour finaliser la vérification et accéder à votre espace.",
			Submit:       "Confirmer",
			Note:         "Vous pouvez fermer cette page après la confirmation.",
			SummaryField: "email",
			SummaryLabel: "Adresse e-mail",
		},
		{
			Lang:         "en",
			Title:        "Confirmation",
			Heading:      "Review and confirm",
			Greeting:     "Thank you",
			Intro:        "The details you submitted have been received. Confirm to complete the verification and access your account.",
			Submit:       "Confirm",
			Note:         "You can close this page after confirming.",
			SummaryField: "email",
			SummaryLabel: "Email address",
		},
		{
			Lang:         "de",
			Title:        "Bestätigung",
			Heading:      "Prüfen und bestätigen",
			Greeting:     "Vielen Dank",
			Intro:        "Ihre Angaben sind eingegangen. Bestätigen Sie, um die Prüfung abzuschließen und auf Ihr Konto zuzugreifen.",
			Submit:       "Bestätigen",
			Note:         "Nach der Bestätigung können Sie diese Seite schließen.",
			SummaryField: "email",
			SummaryLabel: "E-Mail-Adresse",
		},
	}
}
