<?php

/*
 *---------------------------------------------------------------
 * Single FrameWork
 *---------------------------------------------------------------
 * An open source application development framework for PHP 5.2.2 or newer
 *
 * @package		Single FrameWork
 * @author			zeijaku.net
 * @copyright		Copyright (c) 2013
 * @license		Apache License 2.0
 * @link				http://zeijaku.net/
 * @version		Version 1.0
 * @character	UTF-8 
 * @filesource
 */


// --------------------------------------------------
// Request Method
// --------------------------------------------------
	/*
	 * ********************
	 * 存在確認 [$_GET]
	 * ********************
	 * @ val		= GET名
	 * @ security	= XSS=<>&"'をエンティティ化
	 */
	function check_get($val, $security = false)
	{
		$result = "";
		if( isset($_GET[$val]) )
		{
			if( $security == "xss" )
			{
				$result = htmlspecialchars($_GET[$val], ENT_QUOTES, 'UTF-8');
			}
			else
			{
				$result = $_GET[$val];			
			}
		}

		return $result;
	}
	/*
	 * ********************
	 * 存在確認 [$_POST]
	 * ********************
	 * @ val		= POST名
	 * @ security	= XSS=<>&"'をエンティティ化
	 */
	function check_post($val, $security = false)
	{
		$result = "";
		if( isset($_POST[$val]) )
		{
			if( $security == "xss" )
			{
				$result = htmlspecialchars($_POST[$val], ENT_QUOTES, 'UTF-8');
			}
			else
			{
				$result = $_POST[$val];
			}

		}

		return $result;
	}
	/*
	 * ********************
	 * 存在確認 [$_COOKIE]
	 * ********************
	 * @ val		= COOKIE名
	 * @ security	= XSS=<>&"'をエンティティ化
	 */
	function check_cookie($val, $security = false)
	{
		$result = "";
		if( isset($_COOKIE[$val]) )
		{
			if( $security == "xss" )
			{
				$result = htmlspecialchars($_COOKIE[$val], ENT_QUOTES, 'UTF-8');
			}
			else
			{
				$result = $_COOKIE[$val];
			}
		}

		return $result;
	}
	/*
	 * ********************
	 * 存在確認 [$_SERVER]
	 * ********************
	 * @ val		= SERVER名
	 * @ security	= XSS=<>&"'をエンティティ化
	 */
	function check_server($val, $security = false)
	{
		$result = "";
		if( isset($_SERVER[$val]) )
		{
			if( $security == "xss" )
			{
				$result = htmlspecialchars($_SERVER[$val], ENT_QUOTES, 'UTF-8');
			}
			else
			{
				$result = $_SERVER[$val];
			}
		}

		return $result;
	}
	/*
	 * ********************
	 * 存在確認 [$_SESSION]
	 * ********************
	 * @ val		= SESSION名
	 * @ security	= XSS=<>&"'をエンティティ化
	 */
	function check_session($val, $security = false)
	{
		$result = "";
		if( isset($_SESSION[$val]) )
		{
			if( $security == "xss" )
			{
				$result = htmlspecialchars($_SESSION[$val], ENT_QUOTES, 'UTF-8');
			}
			else
			{
				$result = $_SESSION[$val];
			}
		}

		return $result;
	}

// --------------------------------------------------
// Crypt/Decrypt
// --------------------------------------------------
	/*
	 * ********************
	 * 暗号化(簡易)
	 * ********************
	 */
	function encode($val)
	{
		$crypt_target = '';

		$CRYPT_STRENGTH = '2'; // 暗号強度
		$CRYPT_KEY = crypt($CRYPT_STRENGTH);

		$assenble = strlen($val);
		for($i = 0; $i < $assenble; $i++)
		{
			$crypt_target_array[$i] = substr($val, $i, 1);
			$key_array[$i] = substr(crypt($CRYPT_KEY), mt_rand("1", strlen(crypt($CRYPT_KEY)) - 1), 1);
			$crypt_target .= $key_array[$i] . $crypt_target_array[$i];
		}
		$length = intval($CRYPT_STRENGTH);
		for($j = 0; $j < $length; $j++)
		{
			$crypt_target = base64_encode($crypt_target);
		}
		return $crypt_target;
	}
	/*
	 * ********************
	 * 復号化(簡易)
	 * ********************
	 */
	function decode($val)
	{
		$decrypt_target = '';

		$CRYPT_STRENGTH = '2'; // 復号強度
		$CRYPT_KEY = crypt($CRYPT_STRENGTH);

		$length = intval($CRYPT_STRENGTH);
		for($i = 0; $i < $length; $i++)
		{
			$val = base64_decode($val);
		}

		$assenble = strlen($val);
		for($j = 0; $j < $assenble; $j++)
		{
			if( ($j % 2) != 0 )
			{
				$decrypt_target .= substr($val, $j, 1);
			}
		}
		return $decrypt_target;
	}
	/*
	 * ********************
	 * 暗号化・復号化(XOR)
	 * ********************
	 * $val = 対象データ
	 * $salt = 暗号キー
	 */
	function chiper_obfuscation($val, $salt = false)
	{
		$len = strlen($val);
		if( $salt == false )
		{
			$salt = "1";
		}
		else
		{
			$salt = str_split($salt);
			foreach( $salt as $tmp )
			{
				$salt_tmp[] = ord($tmp);
			}	
		}
		$salt_tmp = implode($salt_tmp);
		for( $i = 0; $i < $len; $i++ )
		{
			$seed .= $salt_tmp;
		}
		// XOR暗号
		$enc_val = $val ^ $seed;

		return $enc_val;
	}

// --------------------------------------------------
// Mail
// --------------------------------------------------
	/*
	 * ********************
	 * メール送信
	 * ********************
	 * @ $to = 宛先
	 * @ $subject = 件名
	 * @ $body = 本文
	 * @ $from_email = 返信先
	 * @ $from_name = 返信先名
	 */
	function sendMail($to, $subject, $body, $from_email,$from_name)
	{

		mb_language("ja");
		mb_internal_encoding("UTF-8");

		$headers  = "MIME-Version: 1.0 \n" ;
		$headers .= "From: " .
			   "".mb_encode_mimeheader (mb_convert_encoding($from_name,"ISO-2022-JP","AUTO")) ."" .
			   "<".$from_email."> \n";
		$headers .= "Reply-To: " .
			   "".mb_encode_mimeheader (mb_convert_encoding($from_name,"ISO-2022-JP","AUTO")) ."" .
			   "<".$from_email."> \n";

		$headers .= "Content-Type: text/plain;charset=ISO-2022-JP \n";

		$body = mb_convert_encoding($body, "ISO-2022-JP","AUTO");

		/* Mail, optional paramiters. */
		$sendmail_params  = "-f$from_email";

		$org = mb_internal_encoding();	// 現在のエンコーディングを保存
		mb_internal_encoding("ISO-2022-JP");// 変換対象となる文字列のエンコーディングをセット
		$subject = mb_convert_encoding($subject, "ISO-2022-JP","AUTO");
		$subject = mb_encode_mimeheader($subject);
		mb_internal_encoding($org);// エンコーディングを戻す

		$result = mail($to, $subject, $body, $headers);

		return $result;
	}
// --------------------------------------------------
// Regex
// --------------------------------------------------
	/*
	 * ********************
	 * URL確認
	 * ********************
	 */
	function check_url($url)
	{
		if (preg_match('/^(https?|ftp)(:\/\/[-_.!~*\'()a-zA-Z0-9;\/?:\@&=+\$,%#]+)$/', $url))
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	/*
	 * ********************
	 * Mail確認
	 * ********************
	 */
	function check_mail($mail)
	{
		if (preg_match('/^([a-zA-Z0-9])+([a-zA-Z0-9\._-])*@([a-zA-Z0-9_-])+([a-zA-Z0-9\._-]+)+$/', $mail))
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
// --------------------------------------------------
// Security
// --------------------------------------------------
	/*
	 * ********************
	 * データベースクエリエスケープ
	 * ********************
	 */
	function safe_replace($text) 
	{
		// '"\改行を削除
		$text = preg_replace("/'|\"|\r|\n|\\x00|\\x1a/", '', $text);
		return $text;
	}
// --------------------------------------------------
// Random Create
// --------------------------------------------------
	/*
	 * ********************
	 * ユニークWORD作成
	 * ********************
	 */
	function create_uniq_word($length)
	{
		// トークン生成
		$uniq_id = substr(str_shuffle('abcdefghijklmnopqrstuvwxyz'), 0, $length);
		return $uniq_id;
	}
	/*
	 * ********************
	 * ユニークNUM作成
	 * ********************
	 */
	function create_uniq_num($length)
	{
		// トークン生成
		$uniq_id = substr(str_shuffle('1234567890'), 0, $length);
		return $uniq_id;
	}
// --------------------------------------------------
// Image
//
// @ GD Module Required
// @ Support Type jpeg/gif/png/bmp(GD1.8)
// --------------------------------------------------
	/*
	 * ********************
	 * リサイズ
	 * ********************
	 * @ new_width	= リサイズ後横幅
	 * @ new_height	= リサイズ後縦幅
	 */
	function image_resize($filename, $new_width = false, $new_height = false)
	{
		// サイズ + mimeを取得します
		$img_info = getimagesize($filename);
		list($width, $height) = $img_info;

		// height補正
		if( $new_height == false )
		{
			$parcent = $new_width / $width;
			$new_height = $height * $parcent;
		}

		// 再サンプル
		$image_p = imagecreatetruecolor($new_width, $new_height);
		if( $img_info['mime'] == "image/jpeg" )
		{
			$image = imagecreatefromjpeg($filename);
		}
		elseif( $img_info['mime'] == "image/gif" )
		{
			$image = imagecreatefromgif($filename);
		}
		elseif( $img_info['mime'] == "image/png" or $img_info['mime'] == "image/x-png" )
		{
			$image = imagecreatefrompng($filename);
		}
		elseif( $img_info['mime'] == "image/bmp" or $img_info['mime'] == "image/x-bmp" or $img_info['mime'] == "image/x-ms-bmp" )
		{
			$image = imagecreatefromwbmp($filename);
		}
		imagecopyresampled($image_p, $image, 0, 0, 0, 0, $new_width, $new_height, $width, $height);

		imagedestroy($image);

		// コンテントタイプ
		header("Content-Type: " . $img_info['mime'] . "");
		// 出力
		if( $img_info['mime'] == "image/jpeg" )
		{
			imagejpeg($image_p, null, 100);
		}
		elseif( $img_info['mime'] == "image/gif" )
		{
			imagegif($image_p, null, 100);
		}
		elseif( $img_info['mime'] == "image/png" or $img_info['mime'] == "image/x-png" )
		{
			imagepng($image_p, null, 0);
		}
		elseif( $img_info['mime'] == "image/bmp" or $img_info['mime'] == "image/x-bmp" or $img_info['mime'] == "image/x-ms-bmp" )
		{
			imagewbmp($image_p, null);
		}
		imagedestroy($image_p);
	}
	/*
	 * ********************
	 * 回転
	 * ********************
	 * @ angle			= 角度
	 * @ margincolor	= 余白色
	 */
	function image_rotate($filename, $angle, $margincolor = false)
	{
		// 余白色無指定時
		if( $margincolor == false )
		{
			$margincolor = "0"; // 黒指定
		}

		// 画像情報を取得
		$img_info = getimagesize($filename);

		// 画像データ作成
		if( $img_info['mime'] == "image/jpeg" )
		{
			$image = imagecreatefromjpeg($filename);
		}
		elseif( $img_info['mime'] == "image/gif" )
		{
			$image = imagecreatefromgif($filename);
		}
		elseif( $img_info['mime'] == "image/png" or $img_info['mime'] == "image/x-png" )
		{
			$image = imagecreatefrompng($filename);
		}
		elseif( $img_info['mime'] == "image/bmp" or $img_info['mime'] == "image/x-bmp" or $img_info['mime'] == "image/x-ms-bmp" )
		{
			$image = imagecreatefromwbmp($filename);
		}

		// 回転
		$image_p = imagerotate($image, $angle, $margincolor);

		imagedestroy($image);

		// コンテントタイプ
		header("Content-Type: " . $img_info['mime'] . "");
		// 出力
		if( $img_info['mime'] == "image/jpeg" )
		{
			imagejpeg($image_p, null, 100);
		}
		elseif( $img_info['mime'] == "image/gif" )
		{
			imagegif($image_p, null, 100);
		}
		elseif( $img_info['mime'] == "image/png" or $img_info['mime'] == "image/x-png" )
		{
			imagepng($image_p, null, 0);
		}
		elseif( $img_info['mime'] == "image/bmp" or $img_info['mime'] == "image/x-bmp" or $img_info['mime'] == "image/x-ms-bmp" )
		{
			imagewbmp($image_p, null);
		}
		imagedestroy($image_p);
	}
	/*
	 * ********************
	 * ボカす・モザイク
	 * ********************
	 * @ type	= 0/ズラす 1/ボカす 2/モザイク
	 * @ level	= 効果　小0 <- 3 -> 5大
	 * @ output	= 0/バイナリ出力 1/ファイル保存->ファイルパス 
	 */
	function image_noise($filename, $type = false, $level = false, $output = false)
	{
		// 画像保存先
		$image_folder = "tmp/";

		// タイプ無指定時
		if( $type == false )
		{
			$type = "0";
		}
		// ノイズレベル無指定時
		if( $level == false )
		{
			$level = "2";
		}
		// 出力方法
		if( $output == false )
		{
			$output = "0";
		}

		// 画像情報を取得
		$img_info = getimagesize($filename);

		// 画像データ作成
		if( $img_info['mime'] == "image/jpeg" )
		{
			$dst_im = imagecreatefromjpeg($filename);
		}
		elseif( $img_info['mime'] == "image/gif" )
		{
			$dst_im = imagecreatefromgif($filename);
		}
		elseif( $img_info['mime'] == "image/png" or $img_info['mime'] == "image/x-png" )
		{
			$dst_im = imagecreatefrompng($filename);
		}
		elseif( $img_info['mime'] == "image/bmp" or $img_info['mime'] == "image/x-bmp" or $img_info['mime'] == "image/x-ms-bmp" )
		{
			$dst_im = imagecreatefromwbmp($filename);
		}

		if( $type == "0" )
		{
			/*
			 * ズラす
			 */
			// 出力先
			$image = imagecreatetruecolor($img_info['0'], $img_info['1']);
			// 白で塗りつぶす
			$white = imagecolorallocate($image, 0xFF, 0xFF, 0xFF);
			imagefill($image, 0, 0, $white);

			for( $i = 0; $i < $img_info['1']; $i++ )
			{
				// 揺らぎ生成
				$lag = rand(-$level, 0);
				if( ($i % 2) == "0" )
				{
					$lag = rand(0, $level);
				}
				// 生成
				imagecopy($image, $dst_im, -$level, $i+$level, $lag, $i+$level, $img_info['0']-$level, $img_info['1']);
			}
		}
		elseif( $type == "1" )
		{
			/*
			 * ボカす
			 */
			for( $i = 0; $i < (4 * $level); $i++ )
			{
				imagefilter($dst_im, IMG_FILTER_GAUSSIAN_BLUR);
			}
		}
		elseif( $type == "2" )
		{
			/*
			 * モザイク
			 */
			imagefilter($dst_im, IMG_FILTER_PIXELATE, $img_info['0']/($img_info['0']/4), true);
		}

		//imagedestroy($dst_im);

		// コンテントタイプ
		//header("Content-Type: " . $img_info['mime'] . "");

		/*
		 * 出力
		 */
		if( $img_info['mime'] == "image/jpeg" )
		{
			if( $output == "0" )
			{
				// ダイレクト出力
				$mtime = base64_encode(microtime());
				imagejpeg($dst_im, $image_folder . $mtime . '.jpg', 100);
				$result = file_get_contents($image_folder . $mtime . '.jpg');
				$result_image = 'data:image/jpeg;base64,'.base64_encode($result);
				unlink($image_folder . $mtime . '.jpg');
				return $result_image;
			}
			else
			{
				// ファイル作成 -> ファイル名出力
				$mtime = base64_encode(microtime());
				imagejpeg($dst_im, $image_folder . $mtime . '.jpg', 100);
				$result = $image_folder . $mtime . '.jpg';
				return $result;
			}
		}
		elseif( $img_info['mime'] == "image/gif" )
		{
			if( $output == "0" )
			{
				// ダイレクト出力
				$mtime = base64_encode(microtime());
				imagegif($dst_im, $image_folder . $mtime . '.gif', 100);
				$result = file_get_contents($image_folder . $mtime . '.gif');
				$result_image = 'data:image/gif;base64,'.base64_encode($result);
				unlink($image_folder . $mtime . '.gif');
				return $result_image;			
			}
			else
			{
				// ファイル作成 -> ファイル名出力
				$mtime = base64_encode(microtime());
				imagegif($dst_im, $image_folder . $mtime . '.gif', 100);
				$result = $image_folder . $mtime . '.gif';
				return $result;

			}
		}
		elseif( $img_info['mime'] == "image/png" or $img_info['mime'] == "image/x-png" )
		{
			if( $output == "0" )
			{
				// ダイレクト出力
				$mtime = base64_encode(microtime());
				imagepng($dst_im, $image_folder . $mtime . '.png', 0);
				$result = file_get_contents($image_folder . $mtime . '.png');
				$result_image = 'data:image/png;base64,'.base64_encode($result);
				unlink($image_folder . $mtime . '.png');
				return $result_image;
			}
			else
			{
				// ファイル作成 -> ファイル名出力
				$mtime = base64_encode(microtime());
				imagepng($dst_im, $image_folder . $mtime . '.png', 100);
				$result = $image_folder . $mtime . '.png';
				return $result;

			}
		}
		elseif( $img_info['mime'] == "image/bmp" or $img_info['mime'] == "image/x-bmp" or $img_info['mime'] == "image/x-ms-bmp" )
		{
			if( $output == "0" )
			{
				// ダイレクト出力
				$mtime = base64_encode(microtime());
				imagewbmp($dst_im, $image_folder . $mtime . '.bmp');
				$result = file_get_contents($image_folder . $mtime . '.bmp');
				$result_image = 'data:image/bmp;base64,'.base64_encode($result);
				unlink($image_folder . $mtime . '.bmp');
				return $result_image;
			}
			else
			{
				// ファイル作成 -> ファイル名出力
				$mtime = base64_encode(microtime());
				imagewbmp($dst_im, $image_folder . $mtime . '.bmp', 100);
				$result = $image_folder . $mtime . '.bmp';
				return $result;

			}
		}
		imagedestroy($dst_im);
	
	}
// --------------------------------------------------
// Upload
// --------------------------------------------------
	/*
	 * ********************
	 * ファイルアップロード
	 * ********************
	 * @ $config['upload_folder']	= アップロードファイル保存先
	 * @ $config['upload_char']		= input type="file" name="upload_char"
	 * @ $config['upload_type']		= ファイル種類
	 */
	function file_upload($config = false)
	{
		$error = "";
		$result = array();
		$result['error'] = "";
		

		if( $config != false )
		{
			// アップロードファイル保存先
			$upload_folder = $config['upload_folder'];
			// ファイル識別子
			$upload_char = $config['upload_char'];
			// ファイル種類
			$upload_type = $config['upload_type'];
		}

		if(isset($_FILES[$upload_char]["tmp_name"]))
		{
			// 保存先確認
			if( !is_dir($upload_folder) )
			{
				mkdir($upload_folder, 0755);
			}

			$filename = $_FILES[$upload_char]['name'];
			if(move_uploaded_file($_FILES[$upload_char]['tmp_name'], $upload_folder.$filename)==FALSE)
			{
				// エラーハンドリング
				$error = ( ! isset($_FILES[$upload_char]['error'])) ? 4 : $_FILES[$upload_char]['error'];

				switch($error)
				{
					case 1:
						$result['error'] = 'UPLOAD_ERR_INI_SIZE';
						break;
					case 2:
						$result['error'] = 'UPLOAD_ERR_FORM_SIZE';
						break;
					case 3:
						$result['error'] = 'UPLOAD_ERR_PARTIAL';
						break;
					case 4:
						$result['error'] = 'UPLOAD_ERR_NO_FILE';
						break;
					case 6:
						$result['error'] = 'UPLOAD_ERR_NO_TMP_DIR';
						break;
					case 7:
						$result['error'] = 'UPLOAD_ERR_CANT_WRITE';
						break;
					case 8:
						$result['error'] = 'UPLOAD_ERR_EXTENSION';
						break;
					default :
						$result['error'] = 'UPLOAD_NO_FILE_SELECTED';
						break;
				}
			}
			else
			{
				// 画像情報取得
				$img_info = getimagesize($upload_folder.$filename);
				list($width, $height) = $img_info;

				$result['name'] = $filename;
				$result['type'] = $img_info['mime'];
				$result['path'] = $upload_folder;
				$result['size'] = filesize($upload_folder.$filename);
				$result['width'] = $width;
				$result['height'] = $height;
			}
		}

		return $result;
	}
// --------------------------------------------------
// 圧縮・解凍
//
// @ ZipArchive Module Required
// --------------------------------------------------
	/*
	 * ********************
	 * 圧縮
	 * ********************
	 * @ $archive	= *****.zip[圧縮ファイル名]
	 * @ $file		= array('file1', 'file2', 'file3'.....)[圧縮ファイル内容]
	 * @ $output	= tmp/****.zip[圧縮ファイル出力先]
	 */
	function file_compress($archive, $file, $output = false)
	{
		// 出力先無指定時
		if( $output == false )
		{
			$output = $archive;
		}

		$zip = new ZipArchive();

		if ($zip->open($output.'.zip', ZipArchive::CREATE) === true)
		{
			$file_count = count($file);
			for( $i = 0; $i < $file_count; $i++ )
			{
				$zip->addFile($file[$i]);
			}
			$zip->close();

			$result['name'] = $output.'.zip';
			$result['size'] = filesize($output.'.zip');
			$result['error'] = "";
		}
		else
		{
			$result['error'] = "Open Error";
		}

		return $result;
	}
	/*
	 * ********************
	 * 解凍
	 * ********************
	 * @ $archive	= ****.zip[解凍ファイル名]
	 * @ $file_some = array('file1', 'file2', 'file3'.....)[個別指定解凍ファイル]
	 * @ $output	= ./tmp/[解凍ファイル出力先]
	 */
	function file_uncompress($archive, $file_some = false, $output = false)
	{
		// 個別ファイル指定無
		//if( $file_some == false )
		//{
		//	$file_some = array();
		//}
		// 出力先無指定時
		if( $output == false )
		{
			$output = "./";
		}

		$unzip = new ZipArchive();

		if ($unzip->open($archive) === true)
		{
			if( $file_some == false )
			{
				// 全解凍の場合
				if ($unzip->extractTo($output) === true)
				{
					$unzip->close();

					$result['name'] = $output;
					$result['error'] = "";
				}
				else
				{
					$result['error'] = "Extract Error";
				}
			}
			else
			{
				// 個別解凍ファイルの場合
				if ($unzip->extractTo($output, $file_some) === true)
				{
					$unzip->close();

					$result['name'] = $output;
					$result['error'] = "";
				}
				else
				{
					$result['error'] = "Extract Error";
				}			
			}
		}
		else
		{
			$result['error'] = "Open Error";
		}

		return $result;
	}
// --------------------------------------------------
// Cashe 
// 
// 利用方法
// $obj = new get_contents();
// $obj->cash_get_contents('http://zeijaku.net/');
// --------------------------------------------------
	/*
	 * ********************
	 * キャッシュクラス
	 * ********************
	 * $time_limit = キャッシュ保存期間（秒）
	 * $cache_dir = キャッシュ保存ディレクトリ
	 */
	class get_contents
	{
		function cash_get_contents($url)
		{
			/*
			* 設定
			*/
			// キャッシュ有効時間(秒)
			$time_limit = '60';
			// キャッシュ保存ディレクトリ
			$cache_dir = "./";
			// URL Hash化
			$file_name_hash = md5($url);

			if( !file_exists($cache_dir.$file_name_hash) )
			{
				// 初回アクセス時はファイル作成
				$result =  $this->steal_contents($url);
				file_put_contents($cache_dir.$file_name_hash, $result);
			}
			else
			{
				/*
				* ファイルがある場合はキャッシュ時間を確認
				* 時間内ならキャッシュを、経過していれば新たに取得
				*/
				if (file_exists($cache_dir.$file_name_hash) && (filemtime($cache_dir.$file_name_hash) + $time_limit) < time() ) 
				{
					/*
					* キャッシュする
					*/
					$result = $this->steal_contents($url);
					// file_put_contents でキャッシュ
					file_put_contents($cache_dir.$file_name_hash, $result);
				}
				else
				{
					/*
					* キャッシュを返す
					*/
					$result = file_get_contents($cache_dir.$file_name_hash);
		  
				}
			}
			return $result;
		}

		/*
		* コンテンツ取得
		*/
		function steal_contents($url)
		{
			// curl で取得する
			$ch = curl_init(); // 初期化
			curl_setopt( $ch, CURLOPT_URL, $url );      // オプション設定
			// Location対策
			curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );  // Locationがあれば辿る[safe_modeでは使えない]
			curl_setopt( $ch, CURLOPT_MAXREDIRS, 3 );      // Locationをn回迄辿る
			// タイムアウト設定
			curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 1 );
			curl_setopt( $ch, CURLOPT_TIMEOUT, 0 );
			// SSL証明書を無視
			curl_setopt( $ch,CURLOPT_SSL_VERIFYPEER,false );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYHOST,false );
			// ヘッダーセット
			$request_headers = array();
			array_push($request_headers, "Connection: close");
			array_push($request_headers, "User-Agent: " . htmlspecialchars($_SERVER['HTTP_USER_AGENT']));
			curl_setopt( $ch, CURLOPT_HTTPHEADER, $request_headers );
			// 返り値
			curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );  // 返り値
			curl_setopt( $ch, CURLOPT_BINARYTRANSFER, true );  // 返り値をそのまま取得
			$result = curl_exec( $ch ); // 実行 or 取得
			curl_close($ch); // 終了
			
			return $result;
		}

	}

// --------------------------------------------------
// Error 表示 
// 
// 利用方法
// ファイル最後尾に error_view() を記述
// --------------------------------------------------
	function error_view()
	{
		if( error_get_last() != "" )
		{
			/*
			 * エラー取得
			 */
			$error = "";
			$error = error_get_last();
			/*
			 * エラー元ファイル取得
			 */
			$file = file($error['file']);

			/*
			 * エラー定数判別
			 */
			if( $error['type'] == 1 )
			{
				$error_type = "E_ERROR 重大な実行時エラー。<br />これは、メモリ確保に関する問題のように復帰できないエラーを示します。<br />スクリプトの実行は中断されます。";
			}
			elseif( $error['type'] == 2 )
			{
				$error_type = "E_WARNING 実行時の警告 (致命的なエラーではない)。<br />スクリプトの実行は中断されません。";
			}
			elseif( $error['type'] == 4 )
			{
				$error_type = "E_PARSE コンパイル時のパースエラー。<br />パースエラーはパーサでのみ生成されます。";
			}
			elseif( $error['type'] == 8 )
			{
				$error_type = "E_NOTICE 実行時の警告。<br />エラーを発しうる状況に遭遇したことを示す。 <br />ただし通常のスクリプト実行の場合にもこの警告を発することがありうる。";
			}
			else
			{
				$error_type = $error['type'];
			}

			/*
			 * エラー内容出力
			 */
			echo "<pre>";
			echo "<div style='background-color: #dddddd;'>";
			echo "<span style='color: #ea5506;'>Error Type.</span><br />";
			echo $error_type . "<br />";
			echo "<span style='color: #ea5506;'>Error Message.</span><br />";
			echo $error['message'] . "<br />";
			echo "<span style='color: #ea5506;'>Error File.</span><br />";
			echo $error['file'] . "<br />";
			echo "<span style='color: #ea5506;'>Error Line.</span><br />";
			echo $error['line'] . "<br />";
			echo "</div>";
			echo "<div style='background-color: #cccccc;'>";
			echo "<code>";

			/*
			 * エラー箇所出力
			 */
			for( $i = 0; $i < count($file); $i++ )
			{
				if( $i == $error['line']  )
				{
					echo "<b>" . htmlspecialchars($file[$i-1]) . "</b>";
				}
			}
			echo "</code>";
			echo "</div>";
			echo "</pre>";
		}
	}

// --------------------------------------------------
// 時間 差分取得
// @ PHP5.3 Over
// --------------------------------------------------
	/*
	 * @ $s_point	= 開始時間[形式：yyyy/mm/dd hh:ii:ss]
	 * @ $e_point	= 終了時間[形式：yyyy/mm/dd hh:ii:ss]
	 * @ return		= 差分(秒)
	 */
	function time_diff($s_point = false, $e_point = false)
	{
		$start = new DateTime($s_point);
		$end = new DateTime($e_point);

		$interval = $start->diff($end, true);

		$d = $interval->format('%a') * 24 * 60 * 60;	// s_point -> e_point 日数 => 秒数
		$h = $interval->format('%h') * 60 * 60;			// 時間 => 秒数
		$i = $interval->format('%i') * 60;				// 分 => 秒数
		$s = $interval->format('%s');					// 秒数
		$result = $d + $h + $i + $s;

		if( $start > $end )
		{
			/*
			 * 差分がマイナスの場合はマイナス変換
			 */
			$result = ($result * -1);
		}

		return $result;
	}


/* End of file frame_core.php */
/* Location: ./frame_core.php */