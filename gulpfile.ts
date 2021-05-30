import gulp from 'gulp';
import mocha from 'gulp-mocha';

gulp.task('mocha', () =>
	gulp.src('./test/**/*.ts')
		.pipe(mocha({
			exit: true,
			require: 'ts-node/register'
		} as any))
);

gulp.task('test', gulp.task('mocha'));
