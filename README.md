QSecurity
=========

面临flash的各种xss，多次批量修复总会疲劳，故尽可能的收归一下现有的漏洞！

Example.

package 
		{
			public class Main extends QSecurity 
			{
				public function Main():void 
				{
					super(["*.qq.com","*.gtimg.cn"],0);
				}
				override protected function init():void 
				{
					stage.align = StageAlign.LEFT;
					stage.scaleMode = StageScaleMode.NO_SCALE;
					
					//如：判断一个url是否合法
					if (QSecurity.checkLegalUrl(url))
					{
						this._urlLoader.load(new URLRequest(url));
					}
				}
			}
		}
