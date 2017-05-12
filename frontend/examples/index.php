<?php // INDENTING (emacs/vi): -*- mode:html; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
/** Universal Password Changer (UPwdChg)
 *
 * @package    UPwdChg
 * @subpackage Examples
 */

// Check configuration path
if(!isset($_SERVER['PHP_UPWDCHG_CONFIG'])) {
  trigger_error('Missing configuration path. Please set the PHP_UPWDCHG_CONFIG environment variable.', E_USER_ERROR);
}

// Disable error display (to prevent session data corruption)
// WARNING: Allowing errors to be displayed is a security risk!
//          Do not display errors on a production site!
ini_set('display_errors', 0);

// Set internal character encoding
mb_internal_encoding('UTF-8');

// Start session (required)
session_start();

/** Load and instantiate UPwdChg resources
 */
require_once 'UPwdChg.php';
$oUPwdChg = new UPwdChg($_SERVER['PHP_UPWDCHG_CONFIG']);

// Controller / View
$oUPwdChg->controlPage(); // We MUST do this before anything is sent to the browser (cf. HTTP headers)
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<HTML>
<HEAD>
<META HTTP-EQUIV="content-type" CONTENT="text/html; charset=UTF-8" />
<TITLE><?php echo htmlentities($oUPwdChg->getText('title')); ?></TITLE>
<STYLE TYPE="text/css">
DIV.UPwdChg { WIDTH:600px; MARGIN:auto; FONT:12px sans-serif; BACKGROUND:#FFFFFF; }
DIV.UPwdChg DIV.error { WIDTH:500px; MARGIN:auto; PADDING:5px 10px; BORDER:solid 2px #A00000; BACKGROUND:#FFE0E0; COLOR:#800000; }
DIV.UPwdChg DIV.error H2 { MARGIN:0px; BACKGROUND:transparent; COLOR:#800000; TEXT-ALIGN:center; }
DIV.UPwdChg DIV.error P { MARGIN:0px; BACKGROUND:transparent; COLOR:#800000; TEXT-ALIGN:center; }
DIV.UPwdChg DIV.text { WIDTH:500px; MARGIN:auto; }
DIV.UPwdChg DIV.text P.link { TEXT-ALIGN:center; }
DIV.UPwdChg DIV.form { WIDTH:450px; MARGIN:auto; TEXT-ALIGN:center; }
DIV.UPwdChg DIV.form TABLE { FONT:12px sans-serif; }
DIV.UPwdChg DIV.form TD.label { WIDTH:190px; FONT-WEIGHT:bold; }
DIV.UPwdChg DIV.form TD.input { WIDTH:240px; TEXT-ALIGN:right; }
DIV.UPwdChg DIV.form TD.link { WIDTH:240px; TEXT-ALIGN:center; }
DIV.UPwdChg DIV.form TD.button { PADDING-TOP:20px; TEXT-ALIGN:right; }
DIV.UPwdChg DIV.form INPUT { WIDTH:240px; BACKGROUND:#FCFCFC; BORDER:solid 1px #A0A0A0; }
DIV.UPwdChg DIV.form SPAN.readonly { COLOR:#404040; }
DIV.UPwdChg DIV.form SPAN.readonly INPUT { BACKGROUND:#DCDCDC; BORDER:solid 1px #A0A0A0; }
DIV.UPwdChg DIV.form SPAN.required { COLOR:#C00000; }
DIV.UPwdChg DIV.form SPAN.required INPUT { BACKGROUND:#FFFFF0; BORDER:solid 1px #A08000; }
DIV.UPwdChg DIV.form SELECT { FONT-WEIGHT:bold; }
DIV.UPwdChg DIV.form BUTTON { FONT-WEIGHT:bold; }
DIV.UPwdChg A { TEXT-DECORATION:none; COLOR:#0086FF; }
DIV.UPwdChg A:hover { TEXT-DECORATION:underline; }
</STYLE>
</HEAD>
<BODY>
<DIV CLASS="UPwdChg">
<?php
/** Include localized HTML body
 */
require_once $oUPwdChg->getResourcesDirectory().DIRECTORY_SEPARATOR.$oUPwdChg->getCurrentLocale().'/html.php';
?>
</DIV>
</BODY>
</HTML>
<?php
// Close session
session_write_close();
