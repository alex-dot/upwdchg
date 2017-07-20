<?php // INDENTING (emacs/vi): -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
/** Universal Password Changer (UPwdChg)
 *
 * @package    UPwdChg
 * @subpackage Resources_FR
 */
$_TEXT['title'] = 'Changement de mot de passe';
$_TEXT['label:language'] = 'Langue';
$_TEXT['label:captcha'] = 'Captcha';
$_TEXT['label:username'] = 'Nom d\'utilisateur';
$_TEXT['label:password_old'] = 'Ancien mot de passe';
$_TEXT['label:password_new'] = 'Nouveau mot de passe';
$_TEXT['label:password_confirm'] = '(confirmation)';
$_TEXT['label:password_policy'] = '(règles pour le mot de passe)';
$_TEXT['label:password_policy_back'] = '(retour)';
$_TEXT['label:password_reset'] = 'Mot de passe oublié ? Veuillez s\'il-vous-plaît procéder à sa ré-initialisation...';
$_TEXT['label:password_nonce'] = 'Code PIN';
$_TEXT['label:submit'] = 'Valider';
$_TEXT['label:reset'] = '(recommencer)';
$_TEXT['error:internal_error'] = 'Erreur interne. Veuillez s\'il-vous-plaît prendre contact avec l\'administrateur.';
$_TEXT['error:unsecure_channel'] = 'Canal non sécurisé. Veuillez s\'il-vous-plaît utiliser un canal encrypté (SSL).';
$_TEXT['error:invalid_session'] = 'Session invalide. Veuillez s\'il-vous-plaît recommencer.';
$_TEXT['error:invalid_form_data'] = 'Données invalides. Veuillez s\'il-vous-plaît prendre contact avec l\'administrateur.';
$_TEXT['error:invalid_captcha'] = 'Captcha invalide.';
$_TEXT['error:invalid_credentials'] = 'Codes d\'accès erronés (nom d\'utilisateur, ancien mot de passe ou code PIN).';
$_TEXT['error:expired_password_nonce'] = 'Code PIN expiré.';
$_TEXT['error:password_mismatch'] = 'Erreur de confirmation du mot de passe.';
$_TEXT['error:password_identical'] = 'L\'ancien et le nouveau mot de passe sont identiques.';
$_TEXT['error:password_length_minimum'] = 'Le mot de passe DOIT contenir au moins '.$this->amCONFIG['password_length_minimum'].' caractères.';
$_TEXT['error:password_length_maximum'] = 'Le mot de passe ne doit PAS contenir plus de '.$this->amCONFIG['password_length_maximum'].' caractères.';
$_TEXT['error:password_charset_notascii_required'] = 'Le mot de passe DOIT contenir au moins un caractère non-ASCII.';
$_TEXT['error:password_charset_notascii_forbidden'] = 'Le mot de passe ne doit PAS contenir de caractère non-ASCII.';
$_TEXT['error:password_type_lower_required'] = 'Le mot de passe DOIT contenir au moins un caractère minuscule.';
$_TEXT['error:password_type_lower_forbidden'] = 'Le mot de passe ne doit PAS contenir de caractère minuscule.';
$_TEXT['error:password_type_upper_required'] = 'Le mot de passe DOIT contenir au moins un caractère majuscule.';
$_TEXT['error:password_type_upper_forbidden'] = 'Le mot de passe ne doit PAS contenir de caractère majuscule.';
$_TEXT['error:password_type_digit_required'] = 'Le mot de passe DOIT contenir au moins un chiffre.';
$_TEXT['error:password_type_digit_forbidden'] = 'Le mot de passe ne doit PAS contenir de chiffre.';
$_TEXT['error:password_type_punct_required'] = 'Le mot de passe DOIT contenir au moins une marque de ponctuation.';
$_TEXT['error:password_type_punct_forbidden'] = 'Le mot de passe ne doit PAS contenir de marque de ponctuation.';
$_TEXT['error:password_type_other_required'] = 'Le mot de passe DOIT contenir au moins un caractère spécial.';
$_TEXT['error:password_type_other_forbidden'] = 'Le mot de passe ne doit PAS contenir de caractère spécial.';
$_TEXT['error:password_type_minimum'] = 'Le mot de passe DOIT contenir au moins '.$this->amCONFIG['password_type_minimum'].' types de caractère différents.';
$_TEXT['info:password_nonce_request'] = 'Demande envoyée avec succès. Vous devriez recevoir votre code PIN sous peu.';
$_TEXT['info:password_charset_notascii'] = 'Le mot de passe PEUT contenir des caractères non-ASCII.';
$_TEXT['info:password_type_lower'] = 'Le mot de passe PEUT contenir des caractères minuscules.';
$_TEXT['info:password_type_upper'] = 'Le mot de passe PEUT contenir des caractères majuscules.';
$_TEXT['info:password_type_digit'] = 'Le mot de passe PEUT contenir des chiffres.';
$_TEXT['info:password_type_punct'] = 'Le mot de passe PEUT contenir des marques de ponctuation.';
$_TEXT['info:password_type_other'] = 'Le mot de passe PEUT contenir des caractères spéciaux.';
